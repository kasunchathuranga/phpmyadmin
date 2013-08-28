<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * Database privileges
 *
 * @package PhpMyAdmin
 */

/**
 * Does the common work
 */
require_once 'libraries/common.inc.php';
require_once 'libraries/display_change_password.lib.php';

/**
 * functions implementation for this script
 */
require_once 'libraries/privileges.lib.php';
require_once 'libraries/db_privileges.lib.php';
require 'libraries/db_common.inc.php';

$cfgRelation = PMA_getRelationsParam();

$response = PMA_Response::getInstance();
$header   = $response->getHeader();
$scripts  = $header->getScripts();
$scripts->addFile('db_privileges.js');

/**
 * Adds a user
 */
if (isset($_REQUEST['adduser_submit'])) {
    list($ret_message, $ret_queries, $queries_for_display, $sql_query, $_add_user_error)
        = PMA_addUser(
            isset($_REQUEST['dbname'])? $_REQUEST['dbname'] : null,
            isset($_REQUEST['username'])? $_REQUEST['username'] : null,
            isset($_REQUEST['hostname'])? $_REQUEST['hostname'] : null,
            isset($_REQUEST['password'])? $_REQUEST['password'] : null,
            $cfgRelation['menuswork']
        );
}

if (! empty($_REQUEST['adduser'])) {
    // Add user
    $response->addHTML(
        PMA_getHtmlForAddUser($GLOBALS['db'])
    );
} else {
    // check the privileges for a particular database.
    $response->addHTML(
        PMA_getHtmlForSpecificDbPrivileges()
    );
}
?>