<?php

namespace SimpleSAML\Module\casserver\Cas;

use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Module;
use Symfony\Component\HttpFoundation\Request;
use SimpleSAML\Auth\ProcessingChain;

/**
 * Extract the user and any mapped attributes from the AuthSource attributes
 */
class AttributeExtractor
{
    public const QUERY_PARAM_KEY = 'casserver:queryParams';

    /**
     * Determine the user and any CAS attributes based on the attributes from the
     * authsource and the CAS configuration.
     *
     * The result is an array
     * [
     *   'user' => 'user_value',
     *   'attributes' => [
     *    // any attributes
     * ]
     *
     * If no CAS attributes are configured then the attributes array is empty
     * @param array $state
     * @param \SimpleSAML\Configuration $casconfig
     * @return array
     */
    public function extractUserAndAttributes(array $state, Configuration $casconfig)
    {
        $attributes = $state['Attributes'] ?? [];
        if ($casconfig->hasValue('authproc')) {
            $attributes = $this->invokeAuthProc($state, $casconfig);
        }

        $casUsernameAttribute = $casconfig->getValue('attrname', 'eduPersonPrincipalName');

        $userName = $attributes[$casUsernameAttribute][0] ?? null;
        if (empty($userName)) {
            throw new \Exception("No cas user defined for attribute $casUsernameAttribute");
        }

        if ($casconfig->getValue('attributes', true)) {
            $attributesToTransfer = $casconfig->getValue('attributes_to_transfer', []);

            if (sizeof($attributesToTransfer) > 0) {
                $casAttributes = [];

                foreach ($attributesToTransfer as $key) {
                    if (array_key_exists($key, $attributes)) {
                        $casAttributes[$key] = $attributes[$key];
                    }
                }
            } else {
                $casAttributes = $attributes;
            }
        } else {
            $casAttributes = [];
        }

        return [
            'user' => $userName,
            'attributes' => $casAttributes
        ];
    }


    /**
     * Process any authproc filters defined in the configuration. The Authproc filters must only
     * rely on 'Attributes' being available and not on additional SAML state.
     * @see \SimpleSAML_Auth_ProcessingChain::parseFilter() For the original, SAML side implementation
     * @param array $state
     * @param \SimpleSAML\Configuration $casconfig The cas configuration
     * @return array The attributes post processing.
     */
    private function invokeAuthProc(array $state, Configuration $casconfig)
    {
        // Incase an authproc causes us to lose state
        $state[State::RESTART] = Request::createFromGlobals()->getUri();

        // save our query string so we can reconstruct it after processing
        $state[AttributeExtractor::QUERY_PARAM_KEY] = Request::createFromGlobals()->getQueryString();

        $filters = $casconfig->getArray('authproc', []);
        $idpMetadata = [
            'entityid' => $state['Source']['entityid'] ?? '',
            // ProcessChain needs to know the list of authproc filters from the cas configuration
            'authproc' => $filters,
        ];
        $spMetadata = [
            'entityid' => $state['Destination']['entityid'] ?? '',
        ];

        // Get the ReturnTo from the state or fallback to the login page
        $state['ReturnURL'] = $state['ReturnTo'] ?? Module::getModuleURL('casserver/login.php');
        $state['Destination'] = $spMetadata;
        $state['Source'] = $idpMetadata;

        $chain = new ProcessingChain(
            $state['Source'],
            $state['Destination'],
            'casserver',
        );
        $chain->processState($state);

        return $state['Attributes'];
    }
}
