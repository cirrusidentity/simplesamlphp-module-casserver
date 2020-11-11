<?php

use CirrusIdentity\SSP\Utils\MetricLogger;
use SAML2\DOMDocumentFactory;
use SAML2\Utils;
use SimpleSAML\Logger;
use SimpleSAML\Module\casserver\Cas\Protocol\SamlValidateResponder;

$target = $_GET['TARGET'];

// From SAML2\SOAP::recieve()
$postBody = file_get_contents('php://input');
if (empty($postBody)) {
    throw new \Exception('samlValidate expects a soap body.');
}

$matches = [];
preg_match('@AssertionArtifact>(.*)</samlp:AssertionArtifact@', $postBody, $matches);
if (count($matches) != 2 || empty($matches[1])) {
    throw new \Exception('Missing ticketId in AssertionArtifact');
}

$ticketId = $matches[1];
Logger::debug("samlvalidate: Checking ticket $ticketId");
$casconfig = \SimpleSAML\Configuration::getConfig('module_casserver.php');

$ticketValidator = new \SimpleSAML\Module\casserver\Cas\TicketValidator($casconfig);

$ticket = $ticketValidator->validateAndDeleteTicket($ticketId, $target);
if (!is_array($ticket)) {
    throw new \Exception('Error loading ticket');
}
$msgState = [
    'service' => $target,
    'host' => $_SERVER['SERVER_NAME'],
    'ip' =>  $_SERVER['REMOTE_ADDR'],
    'user' => $ticket['userName'],
    'ticketPrefix' => substr($ticketId, 0, 8),
];
MetricLogger::getInstance()->logMetric('cas', 'samlValidate', $msgState);

$samlValidator = new SamlValidateResponder();
$response = $samlValidator->convertToSaml($ticket);
$soap = $samlValidator->wrapInSoap($response);

echo $soap;
