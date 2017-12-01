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

require_once 'utility/urlUtils.php';

$forceAuthn = isset($_GET['renew']) && $_GET['renew'];
$isPassive = isset($_GET['gateway']) && $_GET['gateway'];
// Determine if client wants us to post or redirect the response. Default is redirect.
$redirect = !(isset($_GET['method']) && 'POST' === $_GET['method']);

$casconfig = SimpleSAML_Configuration::getConfig('module_casserver.php');

$legal_service_urls = $casconfig->getValue('legal_service_urls');

if (isset($_GET['service']) && !checkServiceURL(sanitize($_GET['service']), $legal_service_urls)) {
    $message = 'Service parameter provided to CAS server is not listed as a legal service: [service] = '
        . var_export($_GET['service'], true);
    SimpleSAML_Logger::debug('casserver:' . $message);

    throw new Exception($message);
}

$as = new SimpleSAML_Auth_Simple($casconfig->getValue('authsource'));

if (array_key_exists('scope', $_GET) && is_string($_GET['scope'])) {
    $scopes = $casconfig->getValue('scopes', array());

    if (array_key_exists($_GET['scope'], $scopes)) {
        $idpList = $scopes[$_GET['scope']];
    } else {
        $message = 'Scope parameter provided to CAS server is not listed as legal scope: [scope] = '
            . var_export($_GET['scope'], true);
        SimpleSAML_Logger::debug('casserver:' . $message);

        throw new Exception($message);
    }
}

if (array_key_exists('language', $_GET) && is_string($_GET['language'])) {
    \SimpleSAML\Locale\Language::setLanguageCookie($_GET['language']);
}

$ticketStoreConfig = $casconfig->getValue('ticketstore', array('class' => 'casserver:FileSystemTicketStore'));
$ticketStoreClass = SimpleSAML_Module::resolveClass($ticketStoreConfig['class'], 'Cas_Ticket');
$ticketStore = new $ticketStoreClass($casconfig);

$ticketFactoryClass = SimpleSAML_Module::resolveClass('casserver:TicketFactory', 'Cas_Ticket');
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

if (isset($_GET['service'])) {
    $attributeExtractor = new \sspmod_casserver_Cas_AttributeExtractor();
    $mappedAttributes = $attributeExtractor->extractUserAndAttributes($as->getAttributes(), $casconfig);


    $serviceTicket = $ticketFactory->createServiceTicket(array(
        'service' => $_GET['service'],
        'forceAuthn' => $forceAuthn,
        'userName' => $mappedAttributes['user'],
        'attributes' => $mappedAttributes['attributes'],
        'proxies' => array(),
        'sessionId' => $sessionTicket['id']
    ));

    $ticketStore->addTicket($serviceTicket);
    try {
        $msgState = [
            'service' => $_GET['service'],
            'host' => $_SERVER['SERVER_NAME'],
            'ip' =>  $_SERVER['REMOTE_ADDR'],
            'user' => $mappedAttributes['user'],
            'ticketPrefix' => substr($serviceTicket['id'],0,8),
        ];
        SimpleSAML_Logger::info('cas login: ' . json_encode($msgState, JSON_UNESCAPED_SLASHES));

    } catch (Exception $e) {
        //eat it so we don't interupt the flow
    }
    $parameters['ticket'] = $serviceTicket['id'];

    if ($redirect) {
        SimpleSAML\Utils\HTTP::redirectTrustedURL(SimpleSAML\Utils\HTTP::addURLParameters($_GET['service'],
            $parameters));
    } else {
        SimpleSAML\Utils\HTTP::submitPOSTData($_GET['service'], $parameters);
    }
} else {
    SimpleSAML\Utils\HTTP::redirectTrustedURL(
        SimpleSAML\Utils\HTTP::addURLParameters(SimpleSAML_Module::getModuleURL('casserver/loggedIn.php'), $parameters)
    );
}
