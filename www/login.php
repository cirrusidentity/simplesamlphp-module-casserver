<?php
/*
 *    simpleSAMLphp-casserver is a CAS 1.0 and 2.0 compliant CAS server in the form of a simpleSAMLphp module
 *
 *    Copyright (C) 2013  Bjorn R. Jensen
 *
 *    This library is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU Lesser General Public
 *    License as published by the Free Software Foundation; either
 *    version 2.1 of the License, or (at your option) any later version.
 *
 *    This library is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    Lesser General Public License for more details.
 *
 *    You should have received a copy of the GNU Lesser General Public
 *    License along with this library; if not, write to the Free Software
 *    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Incoming parameters:
 *  service
 *  renew
 *  gateway
 *  entityId
 *  scope
 *  language
 */

use SimpleSAML\Module\casserver\Cas\Protocol\SamlValidateResponder;
use SimpleSAML\Module\casserver\Cas\ServiceValidator;
use SimpleSAML\Locale\Language;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Utils\HTTP;

require_once('utility/urlUtils.php');

$forceAuthn = isset($_GET['renew']) && $_GET['renew'];
$isPassive = isset($_GET['gateway']) && $_GET['gateway'];
// Determine if client wants us to post or redirect the response. Default is redirect.
$redirect = !(isset($_GET['method']) && 'POST' === $_GET['method']);


$casconfig = SimpleSAML_Configuration::getConfig('module_casserver.php');
$serviceValidator = new ServiceValidator($casconfig);

$serviceUrl = isset($_GET['service']) ? $_GET['service'] : (isset($_GET['TARGET']) ? $_GET['TARGET'] : null);

if (isset($serviceUrl)) {
    $serviceCasConfig = $serviceValidator->checkServiceURL(sanitize($serviceUrl));
    if (isset($serviceCasConfig)) {
        // Override the cas configuration to use for this service
        $casconfig = $serviceCasConfig;
    } else {
        $message = 'Service parameter provided to CAS server is not listed as a legal service: [service] = ' .
            var_export($serviceUrl, true);
        Logger::debug('casserver:' . $message);

        throw new \Exception($message);
    }
}


$as = new \SimpleSAML\Auth\Simple($casconfig->getValue('authsource'));

if (array_key_exists('scope', $_GET) && is_string($_GET['scope'])) {
    $scopes = $casconfig->getValue('scopes', array());

    if (array_key_exists($_GET['scope'], $scopes)) {
        $idpList = $scopes[$_GET['scope']];
    } else {
        $message = 'Scope parameter provided to CAS server is not listed as legal scope: [scope] = '
            . var_export($_GET['scope'], true);
        SimpleSAML\Logger::debug('casserver:' . $message);

        throw new Exception($message);
    }
}

if (array_key_exists('language', $_GET) && is_string($_GET['language'])) {
    \SimpleSAML\Locale\Language::setLanguageCookie($_GET['language']);
}

$ticketStoreConfig = $casconfig->getValue('ticketstore', array('class' => 'casserver:FileSystemTicketStore'));
$ticketStoreClass = SimpleSAML\Module::resolveClass($ticketStoreConfig['class'], 'Cas_Ticket');
$ticketStore = new $ticketStoreClass($casconfig);

$ticketFactoryClass = SimpleSAML\Module::resolveClass('casserver:TicketFactory', 'Cas_Ticket');
$ticketFactory = new $ticketFactoryClass($casconfig);

$session = SimpleSAML_Session::getSessionFromRequest();

$sessionTicket = $ticketStore->getTicket($session->getSessionId());
$sessionRenewId = $sessionTicket ? $sessionTicket['renewId'] : null;
$requestRenewId = isset($_REQUEST['renewId']) ? $_REQUEST['renewId'] : null;

if (!$as->isAuthenticated() || ($forceAuthn && $sessionRenewId != $requestRenewId)) {
    $query = array();

    if ($sessionRenewId && $forceAuthn) {
        $query['renewId'] = $sessionRenewId;
    }

    if (isset($_REQUEST['service'])) {
        $query['service'] = $_REQUEST['service'];
    }

    if (isset($_REQUEST['TARGET'])) {
        $query['TARGET'] = $_REQUEST['TARGET'];
    }

    if (isset($_REQUEST['method'])) {
        $query['method'] = $_REQUEST['method'];
    }

    if (isset($_REQUEST['renew'])) {
        $query['renew'] = $_REQUEST['renew'];
    }

    if (isset($_REQUEST['gateway'])) {
        $query['gateway'] = $_REQUEST['gateway'];
    }

    if (array_key_exists('language', $_GET)) {
        $query['language'] = is_string($_GET['language']) ? $_GET['language'] : null;
    }

    if (isset($_REQUEST['debugMode'])) {
        $query['debugMode'] = $_REQUEST['debugMode'];
    }

    $returnUrl = SimpleSAML\Utils\HTTP::getSelfURLNoQuery() . '?' . http_build_query($query);

    $params = array(
        'ForceAuthn' => $forceAuthn,
        'isPassive' => $isPassive,
        'ReturnTo' => $returnUrl,
    );

    if (isset($_GET['entityId'])) {
        $params['saml:idp'] = $_GET['entityId'];
    }

    if (isset($idpList)) {
        if (sizeof($idpList) > 1) {
            $params['saml:IDPList'] = $idpList;
        } else {
            $params['saml:idp'] = $idpList[0];
        }
    }

    $as->login($params);
}

$sessionExpiry = $as->getAuthData('Expire');

if (!is_array($sessionTicket) || $forceAuthn) {
    $sessionTicket = $ticketFactory->createSessionTicket($session->getSessionId(), $sessionExpiry);

    $ticketStore->addTicket($sessionTicket);
}

$parameters = array();

if (array_key_exists('language', $_GET)) {
    $oldLanguagePreferred = SimpleSAML_XHTML_Template::getLanguageCookie();

    if (isset($oldLanguagePreferred)) {
        $parameters['language'] = $oldLanguagePreferred;
    } else {
        if (is_string($_GET['language'])) {
            $parameters['language'] = $_GET['language'];
        }
    }
}

if (isset($serviceUrl)) {
    $attributeExtractor = new \sspmod_casserver_Cas_AttributeExtractor();
    $mappedAttributes = $attributeExtractor->extractUserAndAttributes($as->getAttributes(), $casconfig);


    $serviceTicket = $ticketFactory->createServiceTicket(array(
        'service' => $serviceUrl,
        'forceAuthn' => $forceAuthn,
        'userName' => $mappedAttributes['user'],
        'attributes' => $mappedAttributes['attributes'],
        'proxies' => array(),
        'sessionId' => $sessionTicket['id']
    ));

    $ticketStore->addTicket($serviceTicket);
    try {
        $msgState = [
            'service' => $serviceUrl,
            'host' => $_SERVER['SERVER_NAME'],
            'ip' =>  $_SERVER['REMOTE_ADDR'],
            'user' => $mappedAttributes['user'],
            'ticketPrefix' => substr($serviceTicket['id'],0,8),
        ];
        SimpleSAML\Logger::info('cas login: ' . json_encode($msgState, JSON_UNESCAPED_SLASHES));

    } catch (Exception $e) {
        //eat it so we don't interupt the flow
    }
    $parameters['ticket'] = $serviceTicket['id'];

    $validDebugModes = ['true', 'samlValidate'];
    if (array_key_exists('debugMode',$_GET) && in_array($_GET['debugMode'], $validDebugModes)) {
        if ($_GET['debugMode'] === 'samlValidate') {
            $samlValidate = new SamlValidateResponder();
            $samlResponse = $samlValidate->convertToSaml($serviceTicket);
            $soap = $samlValidate->wrapInSoap($samlResponse);
            echo '<pre>' . htmlspecialchars($soap) . '</pre>';
        } else {
            $method = 'serviceValidate';
            // Fake some options for validateTicket
            $_GET['ticket'] = $serviceTicket['id'];
            // We want to capture the output from echo used in validateTicket
            ob_start();
            require_once 'utility/validateTicket.php';
            $casResponse = ob_get_contents();
            ob_end_clean();
            echo '<pre>' . htmlspecialchars($casResponse) . '</pre>';
        }
    } elseif ($redirect) {
        // always call this to log differences
        $redirectUrl = casAddURLParameters($serviceUrl, $parameters);
        if ($casconfig->getBoolean('noReencode', false)) {
            HTTP::redirectTrustedURL($redirectUrl);
        } else {
            HTTP::redirectTrustedURL(HTTP::addURLParameters($serviceUrl, $parameters));
        }
    } else {
        SimpleSAML\Utils\HTTP::submitPOSTData($serviceUrl, $parameters);
    }
} else {
    SimpleSAML\Utils\HTTP::redirectTrustedURL(
        SimpleSAML\Utils\HTTP::addURLParameters(SimpleSAML\Module::getModuleURL('casserver/loggedIn.php'), $parameters)
    );
}


/**
 * CAS wants to ensure that a service url provided in login matches exactly that provided in service validate.
 * This method avoids SSP's built in redirect which can change that url in certain ways, such as
 * * changing how a ' ' is encoded
 * * not correctly handling url fragments (e.g. #)
 * * not correctly handling query param keys occurring multiple times
 * * some buggy clients don't encode query params correctly
 * which results in either the wrong url being returned to the client, or a service mismatch
 * @param string $url The url to adjust
 * @param array $params The query parameters to add.
 * @return string The url to return
 */
function casAddURLParameters($url, $params)
{
    $url_fragment = explode("#", $url);
    if (strpos($url_fragment[0], "?") === false) {
        $url_fragment[0] .= "?";
    } else {
        $url_fragment[0] .= "&";
    }
    $url_fragment[0] .= http_build_query($params);
    $url = implode("#", $url_fragment);

    try {
        $sspUrl = HTTP::addURLParameters($url, $params);
        if ($url !== $sspUrl) {
            Logger::warning("SSP encodes '$url' incorrectly. Encodes as '$sspUrl");
        }
    } catch (Exception $e) {
        Logger::warning("Error checking url $url" . $e->getTraceAsString());
    }

    return $url;
}