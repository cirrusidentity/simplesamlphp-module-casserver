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
 */

namespace SimpleSAML\Module\casserver\Cas\Protocol;

use SimpleSAML\Configuration;
use CirrusIdentity\SSP\Utils\MetricLogger;

class Cas10
{
    /**
     * @param \SimpleSAML\Configuration $config
     */
    public function __construct(Configuration $config)
    {
    }


    /**
     * @param string $username
     * @return string
     */
    public function getValidateSuccessResponse($username)
    {
        return "yes\n" . $username . "\n";
    }


    /**
     * @param string $errorCode
     * @param string $explanation
     * @return string
     */
    public function getValidateFailureResponse($errorCode, $explanation):string
    {
        $msgState = [
            'service' => $_GET['service'],
            'host' => $_SERVER['SERVER_NAME'],
            'ip' =>  $_SERVER['REMOTE_ADDR'],
            'error' => $explanation,
            'code' => $errorCode
        ];
        MetricLogger::getInstance()->logMetric('cas', 'error', $msgState);

        return "no\n\n";
    }
}
