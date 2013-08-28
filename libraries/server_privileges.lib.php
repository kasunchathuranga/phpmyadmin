<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * set of functions with the Privileges section in pma
 *
 * @package PhpMyAdmin
 */

if (! defined('PHPMYADMIN')) {
    exit;
}

/**
 * Get Html for User Group Dialog
 *
 * @param string $username     username
 * @param bool   $is_menuswork Is menuswork set in configuration
 *
 * @return string html
 */
function PMA_getHtmlForUserGroupDialog($username, $is_menuswork)
{
    $html = '';
    if (! empty($_REQUEST['edit_user_group_dialog']) && $is_menuswork) {
        $dialog = PMA_getHtmlToChooseUserGroup($username);
        $response = PMA_Response::getInstance();
        if ($GLOBALS['is_ajax_request']) {
            $response->addJSON('message', $dialog);
            exit;
        } else {
            $html .= $dialog;
        }
    }

    return $html;
}

/**
 * Escapes wildcard in a database+table specification
 * before using it in a GRANT statement.
 *
 * Escaping a wildcard character in a GRANT is only accepted at the global
 * or database level, not at table level; this is why I remove
 * the escaping character. Internally, in mysql.tables_priv.Db there are
 * no escaping (for example test_db) but in mysql.db you'll see test\_db
 * for a db-specific privilege.
 *
 * @param string $dbname    Database name
 * @param string $tablename Table name
 *
 * @return string the escaped (if necessary) database.table
 */
function PMA_wildcardEscapeForGrant($dbname, $tablename)
{
    if (! strlen($dbname)) {
        $db_and_table = '*.*';
    } else {
        if (strlen($tablename)) {
            $db_and_table = PMA_Util::backquote(
                PMA_Util::unescapeMysqlWildcards($dbname)
            )
            . '.' . PMA_Util::backquote($tablename);
        } else {
            $db_and_table = PMA_Util::backquote($dbname) . '.*';
        }
    }
    return $db_and_table;
}

/**
 * Generates a condition on the user name
 *
 * @param string $initial the user's initial
 *
 * @return string   the generated condition
 */
function PMA_rangeOfUsers($initial = '')
{
    // strtolower() is used because the User field
    // might be BINARY, so LIKE would be case sensitive
    if (! empty($initial)) {
        $ret = " WHERE `User` LIKE '"
            . PMA_Util::sqlAddSlashes($initial, true) . "%'"
            . " OR `User` LIKE '"
            . PMA_Util::sqlAddSlashes(strtolower($initial), true) . "%'";
    } else {
        $ret = '';
    }
    return $ret;
} // end function

/**
 * Displays on which column(s) a table-specific privilege is granted
 *
 * @param array  $columns          columns array
 * @param array  $row              first row from result or boolean false
 * @param string $name_for_select  privilege types - Select_priv, Insert_priv
 *                                 Update_priv, References_priv
 * @param string $priv_for_header  privilege for header
 * @param string $name             privilege name: insert, select, update, references
 * @param string $name_for_dfn     name for dfn
 * @param string $name_for_current name for current
 *
 * @return $html_output             html snippet
 */
function PMA_getHtmlForDisplayColumnPrivileges($columns, $row, $name_for_select,
    $priv_for_header, $name, $name_for_dfn, $name_for_current
) {
    $html_output = '<div class="item" id="div_item_' . $name . '">' . "\n"
        . '<label for="select_' . $name . '_priv">' . "\n"
        . '<code><dfn title="' . $name_for_dfn . '">'
        . $priv_for_header . '</dfn></code>' . "\n"
        . '</label><br />' . "\n"
        . '<select id="select_' . $name . '_priv" name="'
        . $name_for_select . '[]" multiple="multiple" size="8">' . "\n";

    foreach ($columns as $current_column => $current_column_privileges) {
        $html_output .= '<option '
            . 'value="' . htmlspecialchars($current_column) . '"';
        if ($row[$name_for_select] == 'Y'
            || $current_column_privileges[$name_for_current]
        ) {
            $html_output .= ' selected="selected"';
        }
        $html_output .= '>'
            . htmlspecialchars($current_column) . '</option>' . "\n";
    }

    $html_output .= '</select>' . "\n"
        . '<i>' . __('Or') . '</i>' . "\n"
        . '<label for="checkbox_' . $name_for_select
        . '_none"><input type="checkbox"'
        . ' name="' . $name_for_select . '_none" id="checkbox_'
        . $name_for_select . '_none" title="'
        . _pgettext('None privileges', 'None') . '" />'
        . _pgettext('None privileges', 'None') . '</label>' . "\n"
        . '</div>' . "\n";
    return $html_output;
} // end function

/**
 * Get sql query for display privileges table
 *
 * @param string $db       the database
 * @param string $table    the table
 * @param string $username username for database connection
 * @param string $hostname hostname for database connection
 *
 * @return string sql query
 */
function PMA_getSqlQueryForDisplayPrivTable($db, $table, $username, $hostname)
{
    if ($db == '*') {
        return "SELECT * FROM `mysql`.`user`"
            ." WHERE `User` = '" . PMA_Util::sqlAddSlashes($username) . "'"
            ." AND `Host` = '" . PMA_Util::sqlAddSlashes($hostname) . "';";
    } elseif ($table == '*') {
        return "SELECT * FROM `mysql`.`db`"
            ." WHERE `User` = '" . PMA_Util::sqlAddSlashes($username) . "'"
            ." AND `Host` = '" . PMA_Util::sqlAddSlashes($hostname) . "'"
            ." AND '" . PMA_Util::unescapeMysqlWildcards($db) . "'"
            ." LIKE `Db`;";
    }
    return "SELECT `Table_priv`"
        ." FROM `mysql`.`tables_priv`"
        ." WHERE `User` = '" . PMA_Util::sqlAddSlashes($username) . "'"
        ." AND `Host` = '" . PMA_Util::sqlAddSlashes($hostname) . "'"
        ." AND `Db` = '" . PMA_Util::unescapeMysqlWildcards($db) . "'"
        ." AND `Table_name` = '" . PMA_Util::sqlAddSlashes($table) . "';";
}

/**
 * Displays a dropdown to select the user group
 * with menu items configured to each of them.
 *
 * @param string $username username
 *
 * @return string html to select the user group
 */
function PMA_getHtmlToChooseUserGroup($username)
{
    $html_output = '<form class="ajax" id="changeUserGroupForm"'
            . ' action="server_privileges.php" method="post">';
    $params = array('username' => $username);
    $html_output .= PMA_URL_getHiddenInputs($params);
    $html_output .= '<fieldset id="fieldset_user_group_selection">';
    $html_output .= '<legend>' . __('User group') . '</legend>';

    $groupTable = PMA_Util::backquote($GLOBALS['cfg']['Server']['pmadb'])
        . "." . PMA_Util::backquote($GLOBALS['cfg']['Server']['usergroups']);
    $userTable = PMA_Util::backquote($GLOBALS['cfg']['Server']['pmadb'])
        . "." . PMA_Util::backquote($GLOBALS['cfg']['Server']['users']);

    $userGroups = array();
    $sql_query = "SELECT `usergroup` FROM " . $groupTable;
    $result = PMA_queryAsControlUser($sql_query, false);
    if ($result) {
        while ($row = $GLOBALS['dbi']->fetchRow($result)) {
            $userGroups[] = $row[0];
        }
    }
    $GLOBALS['dbi']->freeResult($result);

    $userGroup = '';
    if (isset($GLOBALS['username'])) {
        $sql_query = "SELECT `usergroup` FROM " . $userTable
            . " WHERE `username` = '" . PMA_Util::sqlAddSlashes($username) . "'";
        $userGroup = $GLOBALS['dbi']->fetchValue(
            $sql_query, 0, 0, $GLOBALS['controllink']
        );
    }

    $html_output .= __('User group') . ': ';
    $html_output .= '<select name="userGroup">';
    $html_output .= '<option value=""></option>';
    foreach ($userGroups as $oneUserGroup) {
        $html_output .= '<option value="' . htmlspecialchars($oneUserGroup) . '"'
            . ($oneUserGroup == $userGroup ? ' selected="selected"' : '')
            . '>'
            . htmlspecialchars($oneUserGroup)
            . '</option>';
    }
    $html_output .= '</select>';
    $html_output .= '<input type="hidden" name="changeUserGroup" value="1">';
    $html_output .= '</fieldset>';
    $html_output .= '</form>';
    return $html_output;
}

/**
 * Sets the user group from request values
 *
 * @param string $username  username
 * @param string $userGroup user group to set
 *
 * @return void
 */
function PMA_setUserGroup($username, $userGroup)
{
    $userTable = PMA_Util::backquote($GLOBALS['cfg']['Server']['pmadb'])
        . "." . PMA_Util::backquote($GLOBALS['cfg']['Server']['users']);

    $sql_query = "SELECT `usergroup` FROM " . $userTable
        . " WHERE `username` = '" . PMA_Util::sqlAddSlashes($username) . "'";
    $oldUserGroup = $GLOBALS['dbi']->fetchValue(
        $sql_query, 0, 0, $GLOBALS['controllink']
    );

    if ($oldUserGroup === false) {
        $upd_query = "INSERT INTO " . $userTable . "(`username`, `usergroup`)"
            . " VALUES ('" . PMA_Util::sqlAddSlashes($username) . "', "
            . "'" . PMA_Util::sqlAddSlashes($userGroup) . "')";
    } else {
        if (empty($userGroup)) {
            $upd_query = "DELETE FROM " . $userTable
                . " WHERE `username`='" . PMA_Util::sqlAddSlashes($username) . "'";
        } elseif ($oldUserGroup != $userGroup) {
            $upd_query = "UPDATE " . $userTable
                . " SET `usergroup`='" . PMA_Util::sqlAddSlashes($userGroup) . "'"
                . " WHERE `username`='" . PMA_Util::sqlAddSlashes($username) . "'";
        }
    }
    if (isset($upd_query)) {
        PMA_queryAsControlUser($upd_query);
    }
}

/**
 * Get the HTML snippet for table specific privileges
 *
 * @param string  $username username for database connection
 * @param string  $hostname hostname for database connection
 * @param string  $db       the database
 * @param string  $table    the table
 * @param boolean $columns  columns array
 * @param array   $row      current privileges row
 *
 * @return string $html_output
 */
function PMA_getHtmlForTableSpecificPrivileges(
    $username, $hostname, $db, $table, $columns, $row
) {
    $res = $GLOBALS['dbi']->query(
        'SELECT `Column_name`, `Column_priv`'
        .' FROM `mysql`.`columns_priv`'
        .' WHERE `User`'
        .' = \'' . PMA_Util::sqlAddSlashes($username) . "'"
        .' AND `Host`'
        .' = \'' . PMA_Util::sqlAddSlashes($hostname) . "'"
        .' AND `Db`'
        .' = \'' . PMA_Util::sqlAddSlashes(
            PMA_Util::unescapeMysqlWildcards($db)
        ) . "'"
        .' AND `Table_name`'
        .' = \'' . PMA_Util::sqlAddSlashes($table) . '\';'
    );

    while ($row1 = $GLOBALS['dbi']->fetchRow($res)) {
        $row1[1] = explode(',', $row1[1]);
        foreach ($row1[1] as $current) {
            $columns[$row1[0]][$current] = true;
        }
    }
    $GLOBALS['dbi']->freeResult($res);
    unset($res, $row1, $current);

    $html_output = '<input type="hidden" name="grant_count" '
        . 'value="' . count($row) . '" />' . "\n"
        . '<input type="hidden" name="column_count" '
        . 'value="' . count($columns) . '" />' . "\n"
        . '<fieldset id="fieldset_user_priv">' . "\n"
        . '<legend>' . __('Table-specific privileges')
        . PMA_Util::showHint(
            __('Note: MySQL privilege names are expressed in English')
        )
        . '</legend>' . "\n";

    // privs that are attached to a specific column
    $html_output .= PMA_getHtmlForAttachedPrivilegesToTableSpecificColumn(
        $columns, $row
    );

    // privs that are not attached to a specific column
    $html_output .= '<div class="item">' . "\n"
        . PMA_getHtmlForNotAttachedPrivilegesToTableSpecificColumn($row)
        . '</div>' . "\n";

    // for Safari 2.0.2
    $html_output .= '<div class="clearfloat"></div>' . "\n";

    return $html_output;
}

/**
 * Get HTML snippet for privileges that are attached to a specific column
 *
 * @param string $columns olumns array
 * @param array  $row     first row from result or boolean false
 *
 * @return string $html_output
 */
function PMA_getHtmlForAttachedPrivilegesToTableSpecificColumn($columns, $row)
{
    $html_output = PMA_getHtmlForDisplayColumnPrivileges(
        $columns, $row, 'Select_priv', 'SELECT',
        'select', __('Allows reading data.'), 'Select'
    );

    $html_output .= PMA_getHtmlForDisplayColumnPrivileges(
        $columns, $row, 'Insert_priv', 'INSERT',
        'insert', __('Allows inserting and replacing data.'), 'Insert'
    );

    $html_output .= PMA_getHtmlForDisplayColumnPrivileges(
        $columns, $row, 'Update_priv', 'UPDATE',
        'update', __('Allows changing data.'), 'Update'
    );

    $html_output .= PMA_getHtmlForDisplayColumnPrivileges(
        $columns, $row, 'References_priv', 'REFERENCES', 'references',
        __('Has no effect in this MySQL version.'), 'References'
    );
    return $html_output;
}

/**
 * Get HTML for privileges that are not attached to a specific column
 *
 * @param array $row first row from result or boolean false
 *
 * @return string $html_output
 */
function PMA_getHtmlForNotAttachedPrivilegesToTableSpecificColumn($row)
{
    $html_output = '';
    foreach ($row as $current_grant => $current_grant_value) {
        $grant_type = substr($current_grant, 0, (strlen($current_grant) - 5));
        if (in_array($grant_type, array('Select', 'Insert', 'Update', 'References'))
        ) {
            continue;
        }
        // make a substitution to match the messages variables;
        // also we must substitute the grant we get, because we can't generate
        // a form variable containing blanks (those would get changed to
        // an underscore when receiving the POST)
        if ($current_grant == 'Create View_priv') {
            $tmp_current_grant = 'CreateView_priv';
            $current_grant = 'Create_view_priv';
        } elseif ($current_grant == 'Show view_priv') {
            $tmp_current_grant = 'ShowView_priv';
            $current_grant = 'Show_view_priv';
        } else {
            $tmp_current_grant = $current_grant;
        }

        $html_output .= '<div class="item">' . "\n"
           . '<input type="checkbox"'
           . ' name="' . $current_grant . '" id="checkbox_' . $current_grant
           . '" value="Y" '
           . ($current_grant_value == 'Y' ? 'checked="checked" ' : '')
           . 'title="';

        $html_output .= (isset($GLOBALS[
                    'strPrivDesc' . substr(
                        $tmp_current_grant, 0, (strlen($tmp_current_grant) - 5)
                    )
                ] )
                ? $GLOBALS[
                    'strPrivDesc' . substr(
                        $tmp_current_grant, 0, (strlen($tmp_current_grant) - 5)
                    )
                ]
                : $GLOBALS[
                    'strPrivDesc' . substr(
                        $tmp_current_grant, 0, (strlen($tmp_current_grant) - 5)
                    ) . 'Tbl'
                ]
            )
            . '"/>' . "\n";

        $html_output .= '<label for="checkbox_' . $current_grant
            . '"><code><dfn title="'
            . (isset($GLOBALS[
                    'strPrivDesc' . substr(
                        $tmp_current_grant, 0, (strlen($tmp_current_grant) - 5)
                    )
                ])
                ? $GLOBALS[
                    'strPrivDesc' . substr(
                        $tmp_current_grant, 0, (strlen($tmp_current_grant) - 5)
                    )
                ]
                : $GLOBALS[
                    'strPrivDesc' . substr(
                        $tmp_current_grant, 0, (strlen($tmp_current_grant) - 5)
                    ) . 'Tbl'
                ]
            )
            . '">'
            . strtoupper(
                substr($current_grant, 0, strlen($current_grant) - 5)
            )
            . '</dfn></code></label>' . "\n"
            . '</div>' . "\n";
    } // end foreach ()
    return $html_output;
}

/**
 * Returns all the grants for a certain user on a certain host
 * Used in the export privileges for all users section
 *
 * @param string $user User name
 * @param string $host Host name
 *
 * @return string containing all the grants text
 */
function PMA_getGrants($user, $host)
{
    $grants = $GLOBALS['dbi']->fetchResult(
        "SHOW GRANTS FOR '"
        . PMA_Util::sqlAddSlashes($user) . "'@'"
        . PMA_Util::sqlAddSlashes($host) . "'"
    );
    $response = '';
    foreach ($grants as $one_grant) {
        $response .= $one_grant . ";\n\n";
    }
    return $response;
} // end of the 'PMA_getGrants()' function

/**
 * Update password and get message for password updating
 *
 * @param string $err_url  error url
 * @param string $username username
 * @param string $hostname hostname
 *
 * @return string $message  success or error message after updating password
 */
function PMA_updatePassword($err_url, $username, $hostname)
{
    // similar logic in user_password.php
    $message = '';

    if (empty($_REQUEST['nopass'])
        && isset($_POST['pma_pw'])
        && isset($_POST['pma_pw2'])
    ) {
        if ($_POST['pma_pw'] != $_POST['pma_pw2']) {
            $message = PMA_Message::error(__('The passwords aren\'t the same!'));
        } elseif (empty($_POST['pma_pw']) || empty($_POST['pma_pw2'])) {
            $message = PMA_Message::error(__('The password is empty!'));
        }
    }

    // here $nopass could be == 1
    if (empty($message)) {

        $hashing_function
            = (! empty($_REQUEST['pw_hash']) && $_REQUEST['pw_hash'] == 'old'
                ? 'OLD_'
                : ''
            )
            . 'PASSWORD';

        // in $sql_query which will be displayed, hide the password
        $sql_query        = 'SET PASSWORD FOR \''
            . PMA_Util::sqlAddSlashes($username)
            . '\'@\'' . PMA_Util::sqlAddSlashes($hostname) . '\' = '
            . (($_POST['pma_pw'] == '')
                ? '\'\''
                : $hashing_function . '(\''
                . preg_replace('@.@s', '*', $_POST['pma_pw']) . '\')');

        $local_query      = 'SET PASSWORD FOR \''
            . PMA_Util::sqlAddSlashes($username)
            . '\'@\'' . PMA_Util::sqlAddSlashes($hostname) . '\' = '
            . (($_POST['pma_pw'] == '') ? '\'\'' : $hashing_function
            . '(\'' . PMA_Util::sqlAddSlashes($_POST['pma_pw']) . '\')');

        $GLOBALS['dbi']->tryQuery($local_query)
            or PMA_Util::mysqlDie(
                $GLOBALS['dbi']->getError(), $sql_query, false, $err_url
            );
        $message = PMA_Message::success(
            __('The password for %s was changed successfully.')
        );
        $message->addParam(
            '\'' . htmlspecialchars($username)
            . '\'@\'' . htmlspecialchars($hostname) . '\''
        );
    }
    return $message;
}

/**
 * Revokes privileges and get message and SQL query for privileges revokes
 *
 * @param string $db_and_table wildcard Escaped database+table specification
 * @param string $dbname       database name
 * @param string $tablename    table name
 * @param string $username     username
 * @param string $hostname     host name
 *
 * @return array ($message, $sql_query)
 */
function PMA_getMessageAndSqlQueryForPrivilegesRevoke($db_and_table, $dbname,
    $tablename, $username, $hostname
) {
    $db_and_table = PMA_wildcardEscapeForGrant($dbname, $tablename);

    $sql_query0 = 'REVOKE ALL PRIVILEGES ON ' . $db_and_table
        . ' FROM \''
        . PMA_Util::sqlAddSlashes($username) . '\'@\''
        . PMA_Util::sqlAddSlashes($hostname) . '\';';

    $sql_query1 = 'REVOKE GRANT OPTION ON ' . $db_and_table
        . ' FROM \'' . PMA_Util::sqlAddSlashes($username) . '\'@\''
        . PMA_Util::sqlAddSlashes($hostname) . '\';';

    $GLOBALS['dbi']->query($sql_query0);
    if (! $GLOBALS['dbi']->tryQuery($sql_query1)) {
        // this one may fail, too...
        $sql_query1 = '';
    }
    $sql_query = $sql_query0 . ' ' . $sql_query1;
    $message = PMA_Message::success(
        __('You have revoked the privileges for %s.')
    );
    $message->addParam(
        '\'' . htmlspecialchars($username)
        . '\'@\'' . htmlspecialchars($hostname) . '\''
    );

    return array($message, $sql_query);
}

/**
 * Returns revoke link for a user.
 *
 * @param string $username  User name
 * @param string $hostname  Host name
 * @param string $dbname    Database name
 * @param string $tablename Table name
 *
 * @return HTML code with link
 */
function PMA_getUserRevokeLink($username, $hostname, $dbname = '', $tablename = '')
{
    return '<a  href="server_privileges.php'
        . PMA_URL_getCommon(
            array(
                'username' => $username,
                'hostname' => $hostname,
                'dbname' => $dbname,
                'tablename' => $tablename,
                'revokeall' => 1,
            )
        )
        . '">'
        . PMA_Util::getIcon('b_usrdrop.png', __('Revoke'))
        . '</a>';
}

/**
 * Returns export link for a user.
 *
 * @param string $username User name
 * @param string $hostname Host name
 * @param string $initial  Initial value
 *
 * @return HTML code with link
 */
function PMA_getUserExportLink($username, $hostname, $initial = '')
{
    return '<a class="export_user_anchor ajax"'
        . ' href="server_privileges.php'
        . PMA_URL_getCommon(
            array(
                'username' => $username,
                'hostname' => $hostname,
                'initial' => $initial,
                'export' => 1,
            )
        )
        . '">'
        . PMA_Util::getIcon('b_tblexport.png', __('Export'))
        . '</a>';
}

/**
 * This function return the extra data array for the ajax behavior
 *
 * @param string $password  password
 * @param string $sql_query sql query
 * @param string $hostname  hostname
 * @param string $username  username
 *
 * @return array $extra_data
 */
function PMA_getExtraDataForAjaxBehavior(
    $password, $sql_query, $hostname, $username
) {
    if (isset($GLOBALS['dbname'])) {
        //if (preg_match('/\\\\(?:_|%)/i', $dbname)) {
        if (preg_match('/(?<!\\\\)(?:_|%)/i', $GLOBALS['dbname'])) {
            $dbname_is_wildcard = true;
        } else {
            $dbname_is_wildcard = false;
        }
    }

    $extra_data = array();
    if (strlen($sql_query)) {
        $extra_data['sql_query']
            = PMA_Util::getMessage(null, $sql_query);
    }

    if (isset($_REQUEST['adduser_submit']) || isset($_REQUEST['change_copy'])) {
        /**
         * generate html on the fly for the new user that was just created.
         */
        $new_user_string = '<tr>'."\n"
            . '<td> <input type="checkbox" name="selected_usr[]" '
            . 'id="checkbox_sel_users_"'
            . 'value="'
            . htmlspecialchars($username)
            . '&amp;#27;' . htmlspecialchars($hostname) . '" />'
            . '</td>' . "\n"
            . '<td><label for="checkbox_sel_users_">'
            . (empty($_REQUEST['username'])
                    ? '<span style="color: #FF0000">' . __('Any') . '</span>'
                    : htmlspecialchars($username) ) . '</label></td>' . "\n"
            . '<td>' . htmlspecialchars($hostname) . '</td>' . "\n";

        $new_user_string .= '<td>';

        if (! empty($password) || isset($_POST['pma_pw'])) {
            $new_user_string .= __('Yes');
        } else {
            $new_user_string .= '<span style="color: #FF0000">'
                . __('No')
            . '</span>';
        };

        $new_user_string .= '</td>'."\n";
        $new_user_string .= '<td>'
            . '<code>' . join(', ', PMA_extractPrivInfo('', true)) . '</code>'
            . '</td>'; //Fill in privileges here
        $new_user_string .= '<td class="usrGroup"></td>';
        $new_user_string .= '<td>';

        if ((isset($_POST['Grant_priv']) && $_POST['Grant_priv'] == 'Y')) {
            $new_user_string .= __('Yes');
        } else {
            $new_user_string .= __('No');
        }

        $new_user_string .='</td>';

        $new_user_string .= '<td>'
            . PMA_getUserEditLink($username, $hostname)
            . '</td>' . "\n";
        $new_user_string .= '<td>'
            . PMA_getUserExportLink(
                $username,
                $hostname,
                isset($_GET['initial']) ? $_GET['initial'] : ''
            )
            . '</td>' . "\n";

        $new_user_string .= '</tr>';

        $extra_data['new_user_string'] = $new_user_string;

        /**
         * Generate the string for this alphabet's initial, to update the user
         * pagination
         */
        $new_user_initial = strtoupper(substr($username, 0, 1));
        $new_user_initial_string = '<a href="server_privileges.php'
            . PMA_URL_getCommon(array('initial' => $new_user_initial)) .'">'
            . $new_user_initial . '</a>';
        $extra_data['new_user_initial'] = $new_user_initial;
        $extra_data['new_user_initial_string'] = $new_user_initial_string;
    }

    if (isset($_POST['update_privs'])) {
        $extra_data['db_specific_privs'] = false;
        $extra_data['db_wildcard_privs'] = false;
        if (isset($dbname_is_wildcard)) {
            $extra_data['db_specific_privs'] = ! $dbname_is_wildcard;
            $extra_data['db_wildcard_privs'] = $dbname_is_wildcard;
        }
        $new_privileges = join(', ', PMA_extractPrivInfo('', true));

        $extra_data['new_privileges'] = $new_privileges;
    }

    if (isset($_REQUEST['validate_username'])) {
        $sql_query = "SELECT * FROM `mysql`.`user` WHERE `User` = '"
            . $_REQUEST['username'] . "';";
        $res = $GLOBALS['dbi']->query($sql_query);
        $row = $GLOBALS['dbi']->fetchRow($res);
        if (empty($row)) {
            $extra_data['user_exists'] = false;
        } else {
            $extra_data['user_exists'] = true;
        }
    }

    return $extra_data;
}

/**
 * Get the HTML snippet for change user login information
 *
 * @param string $username username
 * @param string $hostname host name
 *
 * @return string HTML snippet
 */
function PMA_getChangeLoginInformationHtmlForm($username, $hostname)
{
    $choices = array(
        '4' => __('… keep the old one.'),
        '1' => __('… delete the old one from the user tables.'),
        '2' => __(
            '… revoke all active privileges from '
            . 'the old one and delete it afterwards.'
        ),
        '3' => __(
            '… delete the old one from the user tables '
            . 'and reload the privileges afterwards.'
        )
    );

    $class = ' ajax';
    $html_output = '<form action="server_privileges.php" '
        . 'method="post" class="copyUserForm' . $class .'">' . "\n"
        . PMA_URL_getHiddenInputs('', '')
        . '<input type="hidden" name="old_username" '
        . 'value="' . htmlspecialchars($username) . '" />' . "\n"
        . '<input type="hidden" name="old_hostname" '
        . 'value="' . htmlspecialchars($hostname) . '" />' . "\n"
        . '<fieldset id="fieldset_change_copy_user">' . "\n"
        . '<legend>' . __('Change Login Information / Copy User')
        . '</legend>' . "\n"
        . PMA_getHtmlForDisplayLoginInformationFields('change');

    $html_output .= '<fieldset id="fieldset_mode">' . "\n"
        . ' <legend>'
        . __('Create a new user with the same privileges and …')
        . '</legend>' . "\n";
    $html_output .= PMA_Util::getRadioFields(
        'mode', $choices, '4', true
    );
    $html_output .= '</fieldset>' . "\n"
       . '</fieldset>' . "\n";

    $html_output .= '<fieldset id="fieldset_change_copy_user_footer" '
        . 'class="tblFooters">' . "\n"
        . '<input type="submit" name="change_copy" '
        . 'value="' . __('Go') . '" />' . "\n"
        . '</fieldset>' . "\n"
        . '</form>' . "\n";

    return $html_output;
}

/**
 * Provide a line with links to the relevant database and table
 *
 * @param string $url_dbname url database name that urlencode() string
 * @param string $dbname     database name
 * @param string $tablename  table name
 *
 * @return string HTML snippet
 */
function PMA_getLinkToDbAndTable($url_dbname, $dbname, $tablename)
{
    $html_output = '[ ' . __('Database')
        . ' <a href="' . $GLOBALS['cfg']['DefaultTabDatabase']
        . PMA_URL_getCommon(
            array(
                'db' => $url_dbname,
                'reload' => 1
            )
        )
        . '">'
        . htmlspecialchars($dbname) . ': '
        . PMA_Util::getTitleForTarget(
            $GLOBALS['cfg']['DefaultTabDatabase']
        )
        . "</a> ]\n";

    if (strlen($tablename)) {
        $html_output .= ' [ ' . __('Table') . ' <a href="'
            . $GLOBALS['cfg']['DefaultTabTable']
            . PMA_URL_getCommon(
                array(
                    'db' => $url_dbname,
                    'table' => $tablename,
                    'reload' => 1,
                )
            )
            . '">' . htmlspecialchars($tablename) . ': '
            . PMA_Util::getTitleForTarget(
                $GLOBALS['cfg']['DefaultTabTable']
            )
            . "</a> ]\n";
    }
    return $html_output;
}

/**
 * no db name given, so we want all privs for the given user
 * db name was given, so we want all user specific rights for this db
 * So this function returns user rights as an array
 *
 * @param array  $tables              tables
 * @param string $user_host_condition a where clause that containd user's host
 *                                    condition
 * @param string $dbname              database name
 *
 * @return array $db_rights database rights
 */
function PMA_getUserSpecificRights($tables, $user_host_condition, $dbname)
{
    if (! strlen($dbname)) {
        $tables_to_search_for_users = array(
            'tables_priv', 'columns_priv',
        );
        $dbOrTableName = 'Db';
    } else {
        $user_host_condition .=
            ' AND `Db`'
            .' LIKE \''
            . PMA_Util::sqlAddSlashes($dbname, true) . "'";
        $tables_to_search_for_users = array('columns_priv',);
        $dbOrTableName = 'Table_name';
    }

    $db_rights_sqls = array();
    foreach ($tables_to_search_for_users as $table_search_in) {
        if (in_array($table_search_in, $tables)) {
            $db_rights_sqls[] = '
                SELECT DISTINCT `' . $dbOrTableName .'`
                FROM `mysql`.' . PMA_Util::backquote($table_search_in)
               . $user_host_condition;
        }
    }

    $user_defaults = array(
        $dbOrTableName  => '',
        'Grant_priv'    => 'N',
        'privs'         => array('USAGE'),
        'Column_priv'   => true,
    );

    // for the rights
    $db_rights = array();

    $db_rights_sql = '(' . implode(') UNION (', $db_rights_sqls) . ')'
        .' ORDER BY `' . $dbOrTableName .'` ASC';

    $db_rights_result = $GLOBALS['dbi']->query($db_rights_sql);

    while ($db_rights_row = $GLOBALS['dbi']->fetchAssoc($db_rights_result)) {
        $db_rights_row = array_merge($user_defaults, $db_rights_row);
        if (! strlen($dbname)) {
            // only Db names in the table `mysql`.`db` uses wildcards
            // as we are in the db specific rights display we want
            // all db names escaped, also from other sources
            $db_rights_row['Db'] = PMA_Util::escapeMysqlWildcards(
                $db_rights_row['Db']
            );
        }
        $db_rights[$db_rights_row[$dbOrTableName]] = $db_rights_row;
    }

    $GLOBALS['dbi']->freeResult($db_rights_result);

    if (! strlen($dbname)) {
        $sql_query = 'SELECT * FROM `mysql`.`db`'
            . $user_host_condition . ' ORDER BY `Db` ASC';
    } else {
        $sql_query = 'SELECT `Table_name`,'
            .' `Table_priv`,'
            .' IF(`Column_priv` = _latin1 \'\', 0, 1)'
            .' AS \'Column_priv\''
            .' FROM `mysql`.`tables_priv`'
            . $user_host_condition
            .' ORDER BY `Table_name` ASC;';
    }

    $result = $GLOBALS['dbi']->query($sql_query);
    $sql_query = '';

    while ($row = $GLOBALS['dbi']->fetchAssoc($result)) {
        if (isset($db_rights[$row[$dbOrTableName]])) {
            $db_rights[$row[$dbOrTableName]]
                = array_merge($db_rights[$row[$dbOrTableName]], $row);
        } else {
            $db_rights[$row[$dbOrTableName]] = $row;
        }
        if (! strlen($dbname)) {
            // there are db specific rights for this user
            // so we can drop this db rights
            $db_rights[$row['Db']]['can_delete'] = true;
        }
    }
    $GLOBALS['dbi']->freeResult($result);
    return $db_rights;
}

/**
 * Display user rights in table rows(Table specific or database specific privs)
 *
 * @param array  $db_rights user's database rights array
 * @param string $dbname    database name
 * @param string $hostname  host name
 * @param string $username  username
 *
 * @return array $found_rows, $html_output
 */
function PMA_getHtmlForDisplayUserRightsInRows($db_rights, $dbname,
    $hostname, $username
) {
    $html_output = '';
    $found_rows = array();
    // display rows
    if (count($db_rights) < 1) {
        $html_output .= '<tr class="odd">' . "\n"
           . '<td colspan="6"><center><i>' . __('None') . '</i></center></td>' . "\n"
           . '</tr>' . "\n";
    } else {
        $odd_row = true;
        //while ($row = $GLOBALS['dbi']->fetchAssoc($res)) {
        foreach ($db_rights as $row) {
            $found_rows[] = (! strlen($dbname)) ? $row['Db'] : $row['Table_name'];

            $html_output .= '<tr class="' . ($odd_row ? 'odd' : 'even') . '">' . "\n"
                . '<td>'
                . htmlspecialchars(
                    (! strlen($dbname)) ? $row['Db'] : $row['Table_name']
                )
                . '</td>' . "\n"
                . '<td><code>' . "\n"
                . '        '
                . join(
                    ',' . "\n" . '            ',
                    PMA_extractPrivInfo($row, true)
                ) . "\n"
                . '</code></td>' . "\n"
                . '<td>'
                    . ((((! strlen($dbname)) && $row['Grant_priv'] == 'Y')
                        || (strlen($dbname)
                        && in_array('Grant', explode(',', $row['Table_priv']))))
                    ? __('Yes')
                    : __('No'))
                . '</td>' . "\n"
                . '<td>';
            if (! empty($row['Table_privs']) || ! empty ($row['Column_priv'])) {
                $html_output .= __('Yes');
            } else {
                $html_output .= __('No');
            }
            $html_output .= '</td>' . "\n"
               . '<td>';
            $html_output .= PMA_getUserEditLink(
                $username,
                $hostname,
                (! strlen($dbname)) ? $row['Db'] : $dbname,
                (! strlen($dbname)) ? '' : $row['Table_name']
            );
            $html_output .= '</td>' . "\n"
               . '    <td>';
            if (! empty($row['can_delete'])
                || isset($row['Table_name'])
                && strlen($row['Table_name'])
            ) {
                $html_output .= PMA_getUserRevokeLink(
                    $username,
                    $hostname,
                    (! strlen($dbname)) ? $row['Db'] : $dbname,
                    (! strlen($dbname)) ? '' : $row['Table_name']
                );
            }
            $html_output .= '</td>' . "\n"
               . '</tr>' . "\n";
            $odd_row = ! $odd_row;
        } // end while
    } //end if
    return array($found_rows, $html_output);
}

/**
 * Get a HTML table for display user's tabel specific or database specific rights
 *
 * @param string $username username
 * @param string $hostname host name
 * @param string $dbname   database name
 *
 * @return array $html_output, $found_rows
 */
function PMA_getTableForDisplayAllTableSpecificRights(
    $username, $hostname, $dbname
) {
    // table header
    $html_output = PMA_URL_getHiddenInputs('', '')
        . '<input type="hidden" name="username" '
        . 'value="' . htmlspecialchars($username) . '" />' . "\n"
        . '<input type="hidden" name="hostname" '
        . 'value="' . htmlspecialchars($hostname) . '" />' . "\n"
        . '<fieldset>' . "\n"
        . '<legend>'
        . (! strlen($dbname)
            ? __('Database-specific privileges')
            : __('Table-specific privileges')
        )
        . '</legend>' . "\n"
        . '<table class="data">' . "\n"
        . '<thead>' . "\n"
        . '<tr><th>'
        . (! strlen($dbname) ? __('Database') : __('Table'))
        . '</th>' . "\n"
        . '<th>' . __('Privileges') . '</th>' . "\n"
        . '<th>' . __('Grant') . '</th>' . "\n"
        . '<th>'
        . (! strlen($dbname)
            ? __('Table-specific privileges')
            : __('Column-specific privileges')
        )
        . '</th>' . "\n"
        . '<th colspan="2">' . __('Action') . '</th>' . "\n"
        . '</tr>' . "\n"
        . '</thead>' . "\n";

    $user_host_condition = ' WHERE `User`'
        . ' = \'' . PMA_Util::sqlAddSlashes($username) . "'"
        . ' AND `Host`'
        . ' = \'' . PMA_Util::sqlAddSlashes($hostname) . "'";

    // table body
    // get data

    // we also want privielgs for this user not in table `db` but in other table
    $tables = $GLOBALS['dbi']->fetchResult('SHOW TABLES FROM `mysql`;');

    /**
     * no db name given, so we want all privs for the given user
     * db name was given, so we want all user specific rights for this db
     */
    $db_rights = PMA_getUserSpecificRights($tables, $user_host_condition, $dbname);

    ksort($db_rights);

    $html_output .= '<tbody>' . "\n";
    // display rows
    list ($found_rows, $html_out) =  PMA_getHtmlForDisplayUserRightsInRows(
        $db_rights, $dbname, $hostname, $username
    );

    $html_output .= $html_out;
    $html_output .= '</tbody>' . "\n";
    $html_output .='</table>' . "\n";

    return array($html_output, $found_rows);
}

/**
 * Get HTML for display select db
 *
 * @param array $found_rows isset($dbname)) ? $row['Db'] : $row['Table_name']
 *
 * @return string HTML snippet
 */
function PMA_getHtmlForDisplaySelectDbInEditPrivs($found_rows)
{
    $pred_db_array = $GLOBALS['dbi']->fetchResult('SHOW DATABASES;');

    $html_output = '<label for="text_dbname">'
        . __('Add privileges on the following database:') . '</label>' . "\n";
    if (! empty($pred_db_array)) {
        $html_output .= '<select name="pred_dbname" class="autosubmit">' . "\n"
            . '<option value="" selected="selected">'
            . __('Use text field:') . '</option>' . "\n";
        foreach ($pred_db_array as $current_db) {
            $current_db_show = $current_db;
            $current_db = PMA_Util::escapeMysqlWildcards($current_db);
            // cannot use array_diff() once, outside of the loop,
            // because the list of databases has special characters
            // already escaped in $found_rows,
            // contrary to the output of SHOW DATABASES
            if (empty($found_rows) || ! in_array($current_db, $found_rows)) {
                $html_output .= '<option value="'
                    . htmlspecialchars($current_db) . '">'
                    . htmlspecialchars($current_db_show) . '</option>' . "\n";
            }
        }
        $html_output .= '</select>' . "\n";
    }
    $html_output .= '<input type="text" id="text_dbname" name="dbname" required />' . "\n"
        . PMA_Util::showHint(
            __('Wildcards % and _ should be escaped with a \ to use them literally.')
        );
    return $html_output;
}

/**
 * Get HTML for display table in edit privilege
 *
 * @param string $dbname     database naame
 * @param array  $found_rows isset($dbname)) ? $row['Db'] : $row['Table_name']
 *
 * @return string HTML snippet
 */
function PMA_displayTablesInEditPrivs($dbname, $found_rows)
{
    $html_output = '<input type="hidden" name="dbname"
        '. 'value="' . htmlspecialchars($dbname) . '"/>' . "\n";
    $html_output .= '<label for="text_tablename">'
        . __('Add privileges on the following table:') . '</label>' . "\n";

    $result = @$GLOBALS['dbi']->tryQuery(
        'SHOW TABLES FROM ' . PMA_Util::backquote(
            PMA_Util::unescapeMysqlWildcards($dbname)
        ) . ';',
        null,
        PMA_DatabaseInterface::QUERY_STORE
    );

    if ($result) {
        $pred_tbl_array = array();
        while ($row = $GLOBALS['dbi']->fetchRow($result)) {
            if (! isset($found_rows) || ! in_array($row[0], $found_rows)) {
                $pred_tbl_array[] = $row[0];
            }
        }
        $GLOBALS['dbi']->freeResult($result);

        if (! empty($pred_tbl_array)) {
            $html_output .= '<select name="pred_tablename" '
                . 'class="autosubmit">' . "\n"
                . '<option value="" selected="selected">' . __('Use text field')
                . ':</option>' . "\n";
            foreach ($pred_tbl_array as $current_table) {
                $html_output .= '<option '
                    . 'value="' . htmlspecialchars($current_table) . '">'
                    . htmlspecialchars($current_table)
                    . '</option>' . "\n";
            }
            $html_output .= '</select>' . "\n";
        }
    }
    $html_output .= '<input type="text" id="text_tablename" name="tablename" />'
        . "\n";

    return $html_output;
}

/**
 * Get HTML for display the users overview
 * (if less than 50 users, display them immediately)
 *
 * @param array  $result        ran sql query
 * @param array  $db_rights     user's database rights array
 * @param string $pmaThemeImage a image source link
 * @param string $text_dir      text directory
 *
 * @return string HTML snippet
 */
function PMA_getUsersOverview($result, $db_rights, $pmaThemeImage, $text_dir)
{
    while ($row = $GLOBALS['dbi']->fetchAssoc($result)) {
        $row['privs'] = PMA_extractPrivInfo($row, true);
        $db_rights[$row['User']][$row['Host']] = $row;
    }
    @$GLOBALS['dbi']->freeResult($result);

    $html_output
        = '<form name="usersForm" id="usersForm" action="server_privileges.php" '
        . 'method="post">' . "\n"
        . PMA_URL_getHiddenInputs('', '')
        . '<table id="tableuserrights" class="data">' . "\n"
        . '<thead>' . "\n"
        . '<tr><th></th>' . "\n"
        . '<th>' . __('User') . '</th>' . "\n"
        . '<th>' . __('Host') . '</th>' . "\n"
        . '<th>' . __('Password') . '</th>' . "\n"
        . '<th>' . __('Global privileges') . ' '
        . PMA_Util::showHint(
            __('Note: MySQL privilege names are expressed in English')
        )
        . '</th>' . "\n";
    if ($GLOBALS['cfgRelation']['menuswork']) {
        $html_output .= '<th>' . __('User group') . '</th>' . "\n";
    }
    $html_output .= '<th>' . __('Grant') . '</th>' . "\n"
        . '<th colspan="3">' . __('Action') . '</th>' . "\n"
        . '</tr>' . "\n"
        . '</thead>' . "\n";

    $html_output .= '<tbody>' . "\n";
    $html_output .= PMA_getTableBodyForUserRightsTable($db_rights);
    $html_output .= '</tbody>'
        . '</table>' . "\n";

    $html_output .= '<div style="float:left;">'
        . '<img class="selectallarrow"'
        . ' src="' . $pmaThemeImage . 'arrow_' . $text_dir . '.png"'
        . ' width="38" height="22"'
        . ' alt="' . __('With selected:') . '" />' . "\n"
        . '<input type="checkbox" id="usersForm_checkall" class="checkall_box" '
        . 'title="' . __('Check All') . '" /> '
        . '<label for="usersForm_checkall">' . __('Check All') . '</label> '
        . '<i style="margin-left: 2em">' . __('With selected:') . '</i>' . "\n";

    $html_output .= PMA_Util::getButtonOrImage(
        'submit_mult', 'mult_submit', 'submit_mult_export',
        __('Export'), 'b_tblexport.png', 'export'
    );
    $html_output .= '<input type="hidden" name="initial" '
        . 'value="' . (isset($_GET['initial']) ? $_GET['initial'] : '') . '" />';
    $html_output .= '</div>'
        . '<div class="clear_both" style="clear:both"></div>';

    // add/delete user fieldset
    $html_output .= PMA_getFieldsetForAddDeleteUser();
    $html_output .= '</form>' . "\n";

    return $html_output;
}

/**
 * Get table body for 'tableuserrights' table in userform
 *
 * @param array $db_rights user's database rights array
 *
 * @return string HTML snippet
 */
function PMA_getTableBodyForUserRightsTable($db_rights)
{
    if ($GLOBALS['cfgRelation']['menuswork']) {
        $usersTable = PMA_Util::backquote($GLOBALS['cfg']['Server']['pmadb'])
            . "." . PMA_Util::backquote($GLOBALS['cfg']['Server']['users']);
        $sqlQuery = "SELECT * FROM " . $usersTable;
        $result = PMA_queryAsControlUser($sqlQuery, false);
        $groupAssignment = array();
        if ($result) {
            while ($row = $GLOBALS['dbi']->fetchAssoc($result)) {
                $groupAssignment[$row['username']] = $row['usergroup'];
            }
        }
        $GLOBALS['dbi']->freeResult($result);

        $userGroupTable = PMA_Util::backquote($GLOBALS['cfg']['Server']['pmadb'])
            . "." . PMA_Util::backquote($GLOBALS['cfg']['Server']['usergroups']);
        $sqlQuery = "SELECT COUNT(*) FROM " . $userGroupTable;
        $userGroupCount = $GLOBALS['dbi']->fetchValue(
            $sqlQuery, 0, 0, $GLOBALS['controllink']
        );
    }

    $odd_row = true;
    $index_checkbox = 0;
    $html_output = '';
    foreach ($db_rights as $user) {
        ksort($user);
        foreach ($user as $host) {
            $index_checkbox++;
            $html_output .= '<tr class="' . ($odd_row ? 'odd' : 'even') . '">'
                . "\n";
            $html_output .= '<td>'
                . '<input type="checkbox" class="checkall" name="selected_usr[]" '
                . 'id="checkbox_sel_users_'
                . $index_checkbox . '" value="'
                . htmlspecialchars($host['User'] . '&amp;#27;' . $host['Host'])
                . '"'
                . ' /></td>' . "\n";

            $html_output .= '<td><label '
                . 'for="checkbox_sel_users_' . $index_checkbox . '">'
                . (empty($host['User'])
                    ? '<span style="color: #FF0000">' . __('Any') . '</span>'
                    : htmlspecialchars($host['User'])) . '</label></td>' . "\n"
                . '<td>' . htmlspecialchars($host['Host']) . '</td>' . "\n";

            $html_output .= '<td>';
            switch ($host['Password']) {
            case 'Y':
                $html_output .= __('Yes');
                break;
            case 'N':
                $html_output .= '<span style="color: #FF0000">' . __('No')
                    . '</span>';
                break;
            // this happens if this is a definition not coming from mysql.user
            default:
                $html_output .= '--'; // in future version, replace by "not present"
                break;
            } // end switch
            $html_output .= '</td>' . "\n";

            $html_output .= '<td><code>' . "\n"
                . '' . implode(',' . "\n" . '            ', $host['privs']) . "\n"
                . '</code></td>' . "\n";
            if ($GLOBALS['cfgRelation']['menuswork']) {
                $html_output .= '<td class="usrGroup">' . "\n"
                    . (isset($groupAssignment[$host['User']])
                        ? $groupAssignment[$host['User']]
                        : ''
                    )
                    . '</td>' . "\n";
            }
            $html_output .= '<td>'
                . ($host['Grant_priv'] == 'Y' ? __('Yes') : __('No'))
                . '</td>' . "\n";

            $html_output .= '<td class="center">'
                . PMA_getUserEditLink(
                    $host['User'],
                    $host['Host']
                )
                . '</td>';
            if ($GLOBALS['cfgRelation']['menuswork'] && $userGroupCount > 0) {
                if (empty($host['User'])) {
                    $html_output .= '<td class="center"></td>';
                } else {
                    $html_output .= '<td class="center">'
                        . '<a class="edit_user_group_anchor ajax"'
                        . ' href="server_privileges.php'
                        . PMA_URL_getCommon(array('username' => $host['User']))
                        . '">'
                        . PMA_Util::getIcon('b_usrlist.png', __('Edit user group'))
                        . '</a>'
                        . '</td>';
                }
            }
            $html_output .= '<td class="center">'
                . PMA_getUserExportLink(
                    $host['User'],
                    $host['Host'],
                    isset($_GET['initial']) ? $_GET['initial'] : ''
                )
                . '</td>';
            $html_output .= '</tr>';
            $odd_row = ! $odd_row;
        }
    }
    return $html_output;
}

/**
 * Get HTML fieldset for Add/Delete user
 *
 * @return string HTML snippet
 */
function PMA_getFieldsetForAddDeleteUser()
{
    $html_output = '<fieldset id="fieldset_add_user">' . "\n";
    $html_output .= '<a href="server_privileges.php'
        . PMA_URL_getCommon(array('adduser' => 1))
        . '" class="ajax">' . "\n"
        . PMA_Util::getIcon('b_usradd.png')
        . '            ' . __('Add user') . '</a>' . "\n";
    $html_output .= '</fieldset>' . "\n";

    $html_output .= '<fieldset id="fieldset_delete_user">'
        . '<legend>' . "\n"
        . PMA_Util::getIcon('b_usrdrop.png')
        . '            ' . __('Remove selected users') . '' . "\n"
        . '</legend>' . "\n";

    $html_output .= '<input type="hidden" name="mode" value="2" />' . "\n"
        . '('
        . __(
            'Revoke all active privileges from the users '
            . 'and delete them afterwards.'
        )
        . ')'
        . '<br />' . "\n";

    $html_output .= '<input type="checkbox" '
        . 'title="'
        . __('Drop the databases that have the same names as the users.')
        . '" '
        . 'name="drop_users_db" id="checkbox_drop_users_db" />' . "\n";

    $html_output .= '<label for="checkbox_drop_users_db" '
        . 'title="'
        . __('Drop the databases that have the same names as the users.')
        . '">' . "\n"
        . '            '
        . __('Drop the databases that have the same names as the users.')
        . "\n"
        . '</label>' . "\n"
        . '</fieldset>' . "\n";

    $html_output .= '<fieldset id="fieldset_delete_user_footer" class="tblFooters">'
        . "\n";
    $html_output .= '<input type="submit" name="delete" '
        . 'value="' . __('Go') . '" id="buttonGo" '
        . 'class="ajax"/>' . "\n";

    $html_output .= '</fieldset>' . "\n";

    return $html_output;
}

/**
 * Get HTML for Displays the initials
 *
 * @param array $array_initials array for all initials, even non A-Z
 *
 * @return string HTML snippet
 */
function PMA_getHtmlForDisplayTheInitials($array_initials)
{
    // initialize to false the letters A-Z
    for ($letter_counter = 1; $letter_counter < 27; $letter_counter++) {
        if (! isset($array_initials[chr($letter_counter + 64)])) {
            $array_initials[chr($letter_counter + 64)] = false;
        }
    }

    $initials = $GLOBALS['dbi']->tryQuery(
        'SELECT DISTINCT UPPER(LEFT(`User`,1)) FROM `user` ORDER BY `User` ASC',
        null,
        PMA_DatabaseInterface::QUERY_STORE
    );
    while (list($tmp_initial) = $GLOBALS['dbi']->fetchRow($initials)) {
        $array_initials[$tmp_initial] = true;
    }

    // Display the initials, which can be any characters, not
    // just letters. For letters A-Z, we add the non-used letters
    // as greyed out.

    uksort($array_initials, "strnatcasecmp");

    $html_output = '<table id="initials_table" <cellspacing="5">'
        . '<tr>';
    foreach ($array_initials as $tmp_initial => $initial_was_found) {
        if (! empty($tmp_initial)) {
            if ($initial_was_found) {
                $html_output .= '<td>'
                    . '<a class="ajax"'
                    . ' href="server_privileges.php'
                    . PMA_URL_getCommon(array('initial' => $tmp_initial))
                    . '">' . $tmp_initial
                    . '</a>'
                    . '</td>' . "\n";
            } else {
                $html_output .= '<td>' . $tmp_initial . '</td>';
            }
        }
    }
    $html_output .= '<td>'
        . '<a href="server_privileges.php'
        . PMA_URL_getCommon(array('showall' => 1))
        . '" class="nowrap">[' . __('Show all') . ']</a></td>' . "\n";
    $html_output .= '</tr></table>';

    return $html_output;
}

/**
 * Get the database rigths array for Display user overview
 *
 * @return array  $db_rights    database rights array
 */
function PMA_getDbRightsForUserOverview()
{
    // we also want users not in table `user` but in other table
    $tables = $GLOBALS['dbi']->fetchResult('SHOW TABLES FROM `mysql`;');

    $tables_to_search_for_users = array(
        'user', 'db', 'tables_priv', 'columns_priv', 'procs_priv',
    );

    $db_rights_sqls = array();
    foreach ($tables_to_search_for_users as $table_search_in) {
        if (in_array($table_search_in, $tables)) {
            $db_rights_sqls[] = 'SELECT DISTINCT `User`, `Host` FROM `mysql`.`'
                . $table_search_in . '` '
                . (isset($_GET['initial'])
                ? PMA_rangeOfUsers($_GET['initial'])
                : '');
        }
    }
    $user_defaults = array(
        'User'       => '',
        'Host'       => '%',
        'Password'   => '?',
        'Grant_priv' => 'N',
        'privs'      => array('USAGE'),
    );

    // for the rights
    $db_rights = array();

    $db_rights_sql = '(' . implode(') UNION (', $db_rights_sqls) . ')'
        .' ORDER BY `User` ASC, `Host` ASC';

    $db_rights_result = $GLOBALS['dbi']->query($db_rights_sql);

    while ($db_rights_row = $GLOBALS['dbi']->fetchAssoc($db_rights_result)) {
        $db_rights_row = array_merge($user_defaults, $db_rights_row);
        $db_rights[$db_rights_row['User']][$db_rights_row['Host']]
            = $db_rights_row;
    }
    $GLOBALS['dbi']->freeResult($db_rights_result);
    ksort($db_rights);

    return $db_rights;
}

/**
 * Delete user and get message and sql query for delete user in privileges
 *
 * @param string $queries queries
 *
 * @return PMA_message
 */
function PMA_deleteUser($queries)
{
    if (empty($queries)) {
        $message = PMA_Message::error(__('No users selected for deleting!'));
    } else {
        if ($_REQUEST['mode'] == 3) {
            $queries[] = '# ' . __('Reloading the privileges') . ' …';
            $queries[] = 'FLUSH PRIVILEGES;';
        }
        $drop_user_error = '';
        foreach ($queries as $sql_query) {
            if ($sql_query{0} != '#') {
                if (! $GLOBALS['dbi']->tryQuery($sql_query, $GLOBALS['userlink'])) {
                    $drop_user_error .= $GLOBALS['dbi']->getError() . "\n";
                }
            }
        }
        // tracking sets this, causing the deleted db to be shown in navi
        unset($GLOBALS['db']);

        $sql_query = join("\n", $queries);
        if (! empty($drop_user_error)) {
            $message = PMA_Message::rawError($drop_user_error);
        } else {
            $message = PMA_Message::success(
                __('The selected users have been deleted successfully.')
            );
        }
    }
    return array($sql_query, $message);
}

/**
 * Update the privileges and return the success or error message
 *
 * @param string $username  username
 * @param string $hostname  host name
 * @param string $tablename table name
 * @param string $dbname    database name
 *
 * @return PMA_message success message or error message for update
 */
function PMA_updatePrivileges($username, $hostname, $tablename, $dbname)
{
    $db_and_table = PMA_wildcardEscapeForGrant($dbname, $tablename);

    $sql_query0 = 'REVOKE ALL PRIVILEGES ON ' . $db_and_table
        . ' FROM \'' . PMA_Util::sqlAddSlashes($username)
        . '\'@\'' . PMA_Util::sqlAddSlashes($hostname) . '\';';

    if (! isset($_POST['Grant_priv']) || $_POST['Grant_priv'] != 'Y') {
        $sql_query1 = 'REVOKE GRANT OPTION ON ' . $db_and_table
            . ' FROM \'' . PMA_Util::sqlAddSlashes($username) . '\'@\''
            . PMA_Util::sqlAddSlashes($hostname) . '\';';
    } else {
        $sql_query1 = '';
    }

    // Should not do a GRANT USAGE for a table-specific privilege, it
    // causes problems later (cannot revoke it)
    if (! (strlen($tablename) && 'USAGE' == implode('', PMA_extractPrivInfo()))) {
        $sql_query2 = 'GRANT ' . join(', ', PMA_extractPrivInfo())
            . ' ON ' . $db_and_table
            . ' TO \'' . PMA_Util::sqlAddSlashes($username) . '\'@\''
            . PMA_Util::sqlAddSlashes($hostname) . '\'';

        if ((isset($_POST['Grant_priv']) && $_POST['Grant_priv'] == 'Y')
            || (! strlen($dbname)
            && (isset($_POST['max_questions']) || isset($_POST['max_connections'])
            || isset($_POST['max_updates'])
            || isset($_POST['max_user_connections'])))
        ) {
            $sql_query2 .= PMA_getWithClauseForAddUserAndUpdatePrivs();
        }
        $sql_query2 .= ';';
    }
    if (! $GLOBALS['dbi']->tryQuery($sql_query0)) {
        // This might fail when the executing user does not have
        // ALL PRIVILEGES himself.
        // See https://sourceforge.net/p/phpmyadmin/bugs/3270/
        $sql_query0 = '';
    }
    if (isset($sql_query1) && ! $GLOBALS['dbi']->tryQuery($sql_query1)) {
        // this one may fail, too...
        $sql_query1 = '';
    }
    if (isset($sql_query2)) {
        $GLOBALS['dbi']->query($sql_query2);
    } else {
        $sql_query2 = '';
    }
    $sql_query = $sql_query0 . ' ' . $sql_query1 . ' ' . $sql_query2;
    $message = PMA_Message::success(__('You have updated the privileges for %s.'));
    $message->addParam(
        '\'' . htmlspecialchars($username)
        . '\'@\'' . htmlspecialchars($hostname) . '\''
    );

    return array($sql_query, $message);
}

/**
 * Get List of information: Changes / copies a user
 *
 * @return array()
 */
function PMA_getDataForChangeOrCopyUser()
{
    $row = null;
    $queries = null;
    $password = null;

    if (isset($_REQUEST['change_copy'])) {
        $user_host_condition = ' WHERE `User` = '
            . "'". PMA_Util::sqlAddSlashes($_REQUEST['old_username']) . "'"
            . ' AND `Host` = '
            . "'" . PMA_Util::sqlAddSlashes($_REQUEST['old_hostname']) . "';";
        $row = $GLOBALS['dbi']->fetchSingleRow(
            'SELECT * FROM `mysql`.`user` ' . $user_host_condition
        );
        if (! $row) {
            $response = PMA_Response::getInstance();
            $response->addHTML(
                PMA_Message::notice(__('No user found.'))->getDisplay()
            );
            unset($_REQUEST['change_copy']);
        } else {
            extract($row, EXTR_OVERWRITE);
            // Recent MySQL versions have the field "Password" in mysql.user,
            // so the previous extract creates $Password but this script
            // uses $password
            if (! isset($password) && isset($Password)) {
                $password = $Password;
            }
            $queries = array();
        }
    }

    return array($queries, $password);
}

/**
 * Update Data for information: Deletes users
 *
 * @param array $queries queries array
 *
 * @return array
 */
function PMA_getDataForDeleteUsers($queries)
{
    if (isset($_REQUEST['change_copy'])) {
        $selected_usr = array(
            $_REQUEST['old_username'] . '&amp;#27;' . $_REQUEST['old_hostname']
        );
    } else {
        $selected_usr = $_REQUEST['selected_usr'];
        $queries = array();
    }
    foreach ($selected_usr as $each_user) {
        list($this_user, $this_host) = explode('&amp;#27;', $each_user);
        $queries[] = '# '
            . sprintf(
                __('Deleting %s'),
                '\'' . $this_user . '\'@\'' . $this_host . '\''
            )
            . ' ...';
        $queries[] = 'DROP USER \''
            . PMA_Util::sqlAddSlashes($this_user)
            . '\'@\'' . PMA_Util::sqlAddSlashes($this_host) . '\';';

        if (isset($_REQUEST['drop_users_db'])) {
            $queries[] = 'DROP DATABASE IF EXISTS '
                . PMA_Util::backquote($this_user) . ';';
            $GLOBALS['reload'] = true;
        }
    }
    return $queries;
}

/**
 * update Message For Reload
 *
 * @return array
 */
function PMA_updateMessageForReload()
{
    $message = null;
    if (isset($_REQUEST['flush_privileges'])) {
        $sql_query = 'FLUSH PRIVILEGES;';
        $GLOBALS['dbi']->query($sql_query);
        $message = PMA_Message::success(
            __('The privileges were reloaded successfully.')
        );
    }

    if (isset($_REQUEST['validate_username'])) {
        $message = PMA_Message::success();
    }

    return $message;
}

/**
 * update Data For Queries from queries_for_display
 *
 * @param array $queries             queries array
 * @param array $queries_for_display queries arry for display
 *
 * @return null
 */
function PMA_getDataForQueries($queries, $queries_for_display)
{
    $tmp_count = 0;
    foreach ($queries as $sql_query) {
        if ($sql_query{0} != '#') {
            $GLOBALS['dbi']->query($sql_query);
        }
        // when there is a query containing a hidden password, take it
        // instead of the real query sent
        if (isset($queries_for_display[$tmp_count])) {
            $queries[$tmp_count] = $queries_for_display[$tmp_count];
        }
        $tmp_count++;
    }

    return $queries;
}

/**
 * Update DB information: DB, Table, isWildcard
 *
 * @return array
 */
function PMA_getDataForDBInfo()
{
    $dbname = null;
    $tablename = null;
    $db_and_table = null;
    $dbname_is_wildcard = null;

    /**
     * Checks if a dropdown box has been used for selecting a database / table
     */
    if (PMA_isValid($_REQUEST['pred_tablename'])) {
        $tablename = $_REQUEST['pred_tablename'];
    } elseif (PMA_isValid($_REQUEST['tablename'])) {
        $tablename = $_REQUEST['tablename'];
    } else {
        unset($tablename);
    }

    if (PMA_isValid($_REQUEST['pred_dbname'])) {
        $dbname = $_REQUEST['pred_dbname'];
        unset($pred_dbname);
    } elseif (PMA_isValid($_REQUEST['dbname'])) {
        $dbname = $_REQUEST['dbname'];
    } else {
        unset($dbname);
        unset($tablename);
    }

    if (isset($dbname)) {
        $unescaped_db = PMA_Util::unescapeMysqlWildcards($dbname);
        $db_and_table = PMA_Util::backquote($unescaped_db) . '.';
        if (isset($tablename)) {
            $db_and_table .= PMA_Util::backquote($tablename);
        } else {
            $db_and_table .= '*';
        }
    } else {
        $db_and_table = '*.*';
    }

    // check if given $dbname is a wildcard or not
    if (isset($dbname)) {
        //if (preg_match('/\\\\(?:_|%)/i', $dbname)) {
        if (preg_match('/(?<!\\\\)(?:_|%)/i', $dbname)) {
            $dbname_is_wildcard = true;
        } else {
            $dbname_is_wildcard = false;
        }
    }

    return array(
        isset($dbname)? $dbname : null,
        isset($tablename)? $tablename : null,
        $db_and_table,
        $dbname_is_wildcard,
    );
}

/**
 * Get title and textarea for export user definition in Privileges
 *
 * @param string $username username
 * @param string $hostname host name
 *
 * @return array ($title, $export)
 */
function PMA_getListForExportUserDefinition($username, $hostname)
{
    $export = '<textarea class="export" cols="' . $GLOBALS['cfg']['TextareaCols']
        . '" rows="' . $GLOBALS['cfg']['TextareaRows'] . '">';

    if (isset($_REQUEST['selected_usr'])) {
        // export privileges for selected users
        $title = __('Privileges');
        foreach ($_REQUEST['selected_usr'] as $export_user) {
            $export_username = substr($export_user, 0, strpos($export_user, '&'));
            $export_hostname = substr($export_user, strrpos($export_user, ';') + 1);
            $export .= '# '
                . sprintf(
                    __('Privileges for %s'),
                    '`' . htmlspecialchars($export_username)
                    . '`@`' . htmlspecialchars($export_hostname) . '`'
                )
                . "\n\n";
            $export .= PMA_getGrants($export_username, $export_hostname) . "\n";
        }
    } else {
        // export privileges for a single user
        $title = __('User') . ' `' . htmlspecialchars($username)
            . '`@`' . htmlspecialchars($hostname) . '`';
        $export .= PMA_getGrants($username, $hostname);
    }
    // remove trailing whitespace
    $export = trim($export);

    $export .= '</textarea>';

    return array($title, $export);
}

/**
 * Get HTML for display Add userfieldset
 *
 * @return string html output
 */
function PMA_getAddUserHtmlFieldset()
{
    return '<fieldset id="fieldset_add_user">' . "\n"
        . '<a href="server_privileges.php'
        . PMA_URL_getCommon(array('adduser' => 1))
        . '" class="ajax">' . "\n"
        . PMA_Util::getIcon('b_usradd.png')
        . '            ' . __('Add user') . '</a>' . "\n"
        . '</fieldset>' . "\n";
}

/**
 * Get HTML header for display User's properties
 *
 * @param boolean $dbname_is_wildcard whether database name is wildcard or not
 * @param string  $url_dbname         url database name that urlencode() string
 * @param string  $dbname             database name
 * @param string  $username           username
 * @param string  $hostname           host name
 * @param string  $tablename          table name
 *
 * @return string $html_output
 */
function PMA_getHtmlHeaderForDisplayUserProperties(
    $dbname_is_wildcard, $url_dbname, $dbname, $username, $hostname, $tablename
) {
    $html_output = '<h2>' . "\n"
       . PMA_Util::getIcon('b_usredit.png')
       . __('Edit Privileges:') . ' '
       . __('User');

    if (isset($dbname)) {
        $html_output .= ' <i><a href="server_privileges.php'
            . PMA_URL_getCommon(
                array(
                    'username' => $username,
                    'hostname' => $hostname,
                    'dbname' => '',
                    'tablename' => '',
                )
            )
            . '">\'' . htmlspecialchars($username)
            . '\'@\'' . htmlspecialchars($hostname)
            . '\'</a></i>' . "\n";

        $html_output .= ' - ';
        $html_output .= $dbname_is_wildcard ? __('Databases') : __('Database');
        if (isset($_REQUEST['tablename'])) {
            $html_output .= ' <i><a href="server_privileges.php'
                . PMA_URL_getCommon(
                    array(
                        'username' => $username,
                        'hostname' => $hostname,
                        'dbname' => $url_dbname,
                        'tablename' => '',
                    )
                )
                . '">' . htmlspecialchars($dbname)
                . '</a></i>';

            $html_output .= ' - ' . __('Table')
                . ' <i>' . htmlspecialchars($tablename) . '</i>';
        } else {
            $html_output .= ' <i>' . htmlspecialchars($dbname) . '</i>';
        }

    } else {
        $html_output .= ' <i>\'' . htmlspecialchars($username)
            . '\'@\'' . htmlspecialchars($hostname)
            . '\'</i>' . "\n";

    }
    $html_output .= '</h2>' . "\n";

    return $html_output;
}

/**
 * Get HTML snippet for display user overview page
 *
 * @param string $pmaThemeImage a image source link
 * @param string $text_dir      text directory
 *
 * @return string $html_output
 */
function PMA_getHtmlForDisplayUserOverviewPage($pmaThemeImage, $text_dir)
{
    $html_output = '<h2>' . "\n"
       . PMA_Util::getIcon('b_usrlist.png')
       . __('Users overview') . "\n"
       . '</h2>' . "\n";

    $sql_query = 'SELECT *,' .
        "       IF(`Password` = _latin1 '', 'N', 'Y') AS 'Password'" .
        '  FROM `mysql`.`user`';

    $sql_query .= (isset($_REQUEST['initial'])
        ? PMA_rangeOfUsers($_REQUEST['initial'])
        : '');

    $sql_query .= ' ORDER BY `User` ASC, `Host` ASC;';
    $res = $GLOBALS['dbi']->tryQuery(
        $sql_query, null, PMA_DatabaseInterface::QUERY_STORE
    );

    if (! $res) {
        // the query failed! This may have two reasons:
        // - the user does not have enough privileges
        // - the privilege tables use a structure of an earlier version.
        // so let's try a more simple query

        $sql_query = 'SELECT * FROM `mysql`.`user`';
        $res = $GLOBALS['dbi']->tryQuery(
            $sql_query, null, PMA_DatabaseInterface::QUERY_STORE
        );

        if (! $res) {
            $html_output .= PMA_Message::error(__('No Privileges'))->getDisplay();
            $GLOBALS['dbi']->freeResult($res);
            unset($res);
        } else {
            // This message is hardcoded because I will replace it by
            // a automatic repair feature soon.
            $raw = 'Your privilege table structure seems to be older than'
                . ' this MySQL version!<br />'
                . 'Please run the <code>mysql_upgrade</code> command'
                . '(<code>mysql_fix_privilege_tables</code> on older systems)'
                . ' that should be included in your MySQL server distribution'
                . ' to solve this problem!';
            $html_output .= PMA_Message::rawError($raw)->getDisplay();
        }
    } else {
        $db_rights = PMA_getDbRightsForUserOverview();
        // for all initials, even non A-Z
        $array_initials = array();

        /**
         * Displays the initials
         * Also not necassary if there is less than 20 privileges
         */
        if ($GLOBALS['dbi']->numRows($res) > 20 ) {
            $html_output .= PMA_getHtmlForDisplayTheInitials($array_initials);
        }

        /**
        * Display the user overview
        * (if less than 50 users, display them immediately)
        */
        if (isset($_REQUEST['initial'])
            || isset($_REQUEST['showall'])
            || $GLOBALS['dbi']->numRows($res) < 50
        ) {
            $html_output .= PMA_getUsersOverview(
                $res, $db_rights, $pmaThemeImage, $text_dir
            );
        } else {
            $html_output .= PMA_getAddUserHtmlFieldset();
        } // end if (display overview)

        if (! $GLOBALS['is_ajax_request']
            || ! empty($_REQUEST['ajax_page_request'])
        ) {
            $flushnote = new PMA_Message(
                __(
                    'Note: phpMyAdmin gets the users\' privileges directly '
                    . 'from MySQL\'s privilege tables. The content of these tables '
                    . 'may differ from the privileges the server uses, '
                    . 'if they have been changed manually. In this case, '
                    . 'you should %sreload the privileges%s before you continue.'
                ),
                PMA_Message::NOTICE
            );
            $flushLink = '<a href="server_privileges.php'
                . PMA_URL_getCommon(array('flush_privileges' => 1))
                . '" id="reload_privileges_anchor">';
            $flushnote->addParam(
                $flushLink,
                false
            );
            $flushnote->addParam('</a>', false);
            $html_output .= $flushnote->getDisplay();
        }
    }

    return $html_output;
}

/**
 * Return HTML to list the users belonging to a given user group
 *
 * @param string $userGroup user group name
 *
 * @return HTML to list the users belonging to a given user group
 */
function PMA_getHtmlForListingUsersofAGroup($userGroup)
{
    $html_output  = '<h2>'
        . sprintf(__('Users of \'%s\' user group'), htmlspecialchars($userGroup))
        . '</h2>';

    $usersTable = PMA_Util::backquote($GLOBALS['cfg']['Server']['pmadb'])
        . "." . PMA_Util::backquote($GLOBALS['cfg']['Server']['users']);
    $sql_query = "SELECT `username` FROM " . $usersTable
        . " WHERE `usergroup`='" . PMA_Util::sqlAddSlashes($userGroup) . "'";
    $result = PMA_queryAsControlUser($sql_query, false);
    if ($result) {
        if ($GLOBALS['dbi']->numRows($result) == 0) {
            $html_output .= '<p>'
                . __('No users were found belonging to this user group.')
                . '</p>';
        } else {
            $html_output .= '<table>'
                . '<thead><tr><th>#</th><th>' . __('User') . '</th></tr></thead>'
                . '<tbody>';
            $i = 0;
            while ($row = $GLOBALS['dbi']->fetchRow($result)) {
                $i++;
                $html_output .= '<tr>'
                    . '<td>' . $i . ' </td>'
                    . '<td>' . htmlspecialchars($row[0]) . '</td>'
                    . '</tr>';
            }
            $html_output .= '</tbody>'
                . '</table>';
        }
    }
    $GLOBALS['dbi']->freeResult($result);
    return $html_output;
}

/**
 * Returns HTML for the 'user groups' table
 *
 * @return string HTML for the 'user groups' table
 */
function PMA_getHtmlForUserGroupsTable()
{
    $tabs = PMA_Util::getMenuTabList();

    $html_output  = '<h2>' . __('User groups') . '</h2>';
    $groupTable = PMA_Util::backquote($GLOBALS['cfg']['Server']['pmadb'])
        . "." . PMA_Util::backquote($GLOBALS['cfg']['Server']['usergroups']);
    $sql_query = "SELECT * FROM " . $groupTable . " ORDER BY `usergroup` ASC";
    $result = PMA_queryAsControlUser($sql_query, false);

    if ($result && $GLOBALS['dbi']->numRows($result)) {
        $html_output .= '<form name="userGroupsForm" id="userGroupsForm"'
            . ' action="server_privileges.php" method="post">';
        $html_output .= PMA_URL_getHiddenInputs();
        $html_output .= '<table id="userGroupsTable">';
        $html_output .= '<thead><tr>';
        $html_output .= '<th style="white-space: nowrap">'
            . __('User group') . '</th>';
        $html_output .= '<th>' . __('Server level tabs') . '</th>';
        $html_output .= '<th>' . __('Database level tabs') . '</th>';
        $html_output .= '<th>' . __('Table level tabs') . '</th>';
        $html_output .= '<th>' . __('Action') . '</th>';
        $html_output .= '</tr></thead>';
        $html_output .= '<tbody>';

        $odd = true;
        while ($row = $GLOBALS['dbi']->fetchAssoc($result)) {
            $html_output .= '<tr class="' . ($odd ? 'odd' : 'even') . '">';
            $html_output .= '<td>' . htmlspecialchars($row['usergroup']) . '</td>';
            $html_output .= '<td>' . _getAllowedTabNames($row, 'server') . '</td>';
            $html_output .= '<td>' . _getAllowedTabNames($row, 'db') . '</td>';
            $html_output .= '<td>' . _getAllowedTabNames($row, 'table') . '</td>';

            $html_output .= '<td>';
            $html_output .= '<a class="" href="server_user_groups.php?'
                . PMA_URL_getCommon(
                    array(
                        'viewUsers' => 1, 'userGroup' => $row['usergroup']
                    )
                )
                . '">'
                . PMA_Util::getIcon('b_usrlist.png', __('View users')) . '</a>';
            $html_output .= '&nbsp;&nbsp;';
            $html_output .= '<a class="" href="server_user_groups.php?'
                . PMA_URL_getCommon(
                    array(
                        'editUserGroup' => 1, 'userGroup' => $row['usergroup']
                    )
                )
                . '">'
                . PMA_Util::getIcon('b_edit.png', __('Edit')) . '</a>';
            $html_output .= '&nbsp;&nbsp;';
            $html_output .= '<a class="deleteUserGroup ajax"'
                . ' href="server_user_groups.php?'
                . PMA_URL_getCommon(
                    array(
                        'deleteUserGroup' => 1, 'userGroup' => $row['usergroup']
                    )
                )
                . '">'
                . PMA_Util::getIcon('b_drop.png', __('Delete')) . '</a>';
            $html_output .= '</td>';

            $html_output .= '</tr>';

            $odd = ! $odd;
        }

        $html_output .= '</tbody>';
        $html_output .= '</table>';
        $html_output .= '</form>';
    }
    $GLOBALS['dbi']->freeResult($result);

    $html_output .= '<fieldset id="fieldset_add_user_group">';
    $html_output .= '<a href="server_user_groups.php'
        . PMA_URL_getCommon(array('addUserGroup' => 1)) . '">'
        . PMA_Util::getIcon('b_usradd.png')
        . __('Add user group') . '</a>';
    $html_output .= '</fieldset>';

    return $html_output;
}

/**
 * Returns the list of allowed menu tab names
 * based on a data row from usergroup table.
 *
 * @param array  $row   row of usergroup table
 * @param string $level 'server', 'db' or 'table'
 *
 * @return string comma seperated list of allowed menu tab names
 */
function _getAllowedTabNames($row, $level)
{
    $tabNames = array();
    $tabs = PMA_Util::getMenuTabList($level);
    foreach ($tabs as $tab => $tabName) {
        if (! isset($row[$level . '_' . $tab])
            || $row[$level . '_' . $tab] == 'Y'
        ) {
            $tabNames[] = $tabName;
        }
    }
    return implode(', ', $tabNames);
}

/**
 * Deletes a user group
 *
 * @param string $userGroup user group name
 *
 * @return void
 */
function PMA_deleteUserGroup($userGroup)
{
    $userTable = PMA_Util::backquote($GLOBALS['cfg']['Server']['pmadb'])
        . "." . PMA_Util::backquote($GLOBALS['cfg']['Server']['users']);
    $groupTable = PMA_Util::backquote($GLOBALS['cfg']['Server']['pmadb'])
        . "." . PMA_Util::backquote($GLOBALS['cfg']['Server']['usergroups']);
    $sql_query = "DELETE FROM " . $userTable
        . " WHERE `usergroup`='" . PMA_Util::sqlAddSlashes($userGroup) . "'";
    PMA_queryAsControlUser($sql_query, true);
    $sql_query = "DELETE FROM " . $groupTable
        . " WHERE `usergroup`='" . PMA_Util::sqlAddSlashes($userGroup) . "'";
    PMA_queryAsControlUser($sql_query, true);
}

/**
 * Returns HTML for add/edit user group dialog
 *
 * @param string $userGroup name of the user group in case of editing
 *
 * @return string HTML for add/edit user group dialog
 */
function PMA_getHtmlToEditUserGroup($userGroup = null)
{
    $html_output = '';
    if ($userGroup == null) {
        $html_output .= '<h2>' . __('Add user group') . '</h2>';
    } else {
        $html_output .= '<h2>'
            . sprintf(__('Edit user group: \'%s\''), htmlspecialchars($userGroup))
            . '</h2>';
    }

    $html_output .= '<form name="userGroupForm" id="userGroupForm"'
        . ' action="server_user_groups.php" method="post">';
    $urlParams = array();
    if ($userGroup != null) {
        $urlParams['userGroup'] = $userGroup;
        $urlParams['editUserGroupSubmit'] = '1';
    } else {
        $urlParams['addUserGroupSubmit'] = '1';
    }
    $html_output .= PMA_URL_getHiddenInputs($urlParams);

    $html_output .= '<fieldset id="fieldset_user_group_rights">';
    $html_output .= '<legend>' . __('User group menu assignments')
        . '&nbsp;&nbsp;&nbsp;'
        . '<input type="checkbox" class="checkall_box" title="Check All">'
        . '<label for="addUsersForm_checkall">' . __('Check All') .'</label>'
        . '</legend>';

    if ($userGroup == null) {
        $html_output .= '<label for="userGroup">' . __('Group name:') . '</label>';
        $html_output .= '<input type="text" name="userGroup" autocomplete="off" required />';
        $html_output .= '<div class="clearfloat"></div>';
    }

    $allowedTabs = array(
        'server' => array(),
        'db'     => array(),
        'table'	 => array()
    );
    if ($userGroup != null) {
        $groupTable = PMA_Util::backquote($GLOBALS['cfg']['Server']['pmadb'])
            . "." . PMA_Util::backquote($GLOBALS['cfg']['Server']['usergroups']);
        $sql_query = "SELECT * FROM " . $groupTable
            . " WHERE `usergroup`='" . PMA_Util::sqlAddSlashes($userGroup) . "'";
        $result = PMA_queryAsControlUser($sql_query, false);
        if ($result) {
            $row = $GLOBALS['dbi']->fetchAssoc($result);
            foreach ($row as $key => $value) {
                if (substr($key, 0, 7) == 'server_' && $value == 'Y') {
                    $allowedTabs['server'][] = substr($key, 7);
                } elseif (substr($key, 0, 3) == 'db_' && $value == 'Y') {
                    $allowedTabs['db'][] = substr($key, 3);
                } elseif (substr($key, 0, 6) == 'table_' && $value == 'Y') {
                    $allowedTabs['table'][] = substr($key, 6);
                }
            }
        }
        $GLOBALS['dbi']->freeResult($result);
    }

    $html_output .= _getTabList(
        __('Server-level tabs'), 'server', $allowedTabs['server']
    );
    $html_output .= _getTabList(
        __('Database-level tabs'), 'db', $allowedTabs['db']
    );
    $html_output .= _getTabList(
        __('Table-level tabs'), 'table', $allowedTabs['table']
    );

    $html_output .= '</fieldset>';

    $html_output .= '<fieldset id="fieldset_user_group_rights_footer"'
        . ' class="tblFooters">';
    $html_output .= '<input type="submit" name="update_privs" value="Go">';
    $html_output .= '</fieldset>';

    return $html_output;
}

/**
 * Returns HTML for checkbox groups to choose
 * tabs of 'server', 'db' or 'table' levels.
 *
 * @param string $title    title of the checkbox group
 * @param string $level    'server', 'db' or 'table'
 * @param array  $selected array of selected allowed tabs
 *
 * @return string HTML for checkbox groups
 */
function _getTabList($title, $level, $selected)
{
    $tabs = PMA_Util::getMenuTabList($level);
    $html_output = '<fieldset>';
    $html_output .= '<legend>' . $title . '</legend>';
    foreach ($tabs as $tab => $tabName) {
        $html_output .= '<div class="item">';
        $html_output .= '<input type="checkbox" class="checkall"'
            . (in_array($tab, $selected) ? ' checked="checked"' : '')
            . ' name="' . $level . '_' . $tab .  '" value="Y" />';
        $html_output .= '<label for="' . $level . '_' . $tab .  '">'
            . '<code>' . $tabName . '</code>'
            . '</label>';
        $html_output .= '</div>';
    }
    $html_output .= '</fieldset>';
    return $html_output;
}

/**
 * Add/update a user group with allowed menu tabs.
 *
 * @param string  $userGroup user group name
 * @param boolean $new       whether this is a new user group
 *
 * @return void
 */
function PMA_editUserGroup($userGroup, $new = false)
{
    $tabs = PMA_Util::getMenuTabList();
    $groupTable = PMA_Util::backquote($GLOBALS['cfg']['Server']['pmadb'])
        . "." . PMA_Util::backquote($GLOBALS['cfg']['Server']['usergroups']);

    $cols = "";
    $vals = "";
    $colsNvals = "";
    foreach ($tabs as $tabGroupName => $tabGroup) {
        foreach ($tabs[$tabGroupName] as $tab => $tabName) {
            $colName = $tabGroupName . '_' . $tab;
            $cols .= "," . PMA_Util::backquote($colName);
            if (isset($_REQUEST[$colName])&& $_REQUEST[$colName] == 'Y') {
                $vals .= ",'Y'";
                $colsNvals .= "," . PMA_Util::backquote($colName) . "='Y'";
            } else {
                $vals .= ",'N'";
                $colsNvals .= "," . PMA_Util::backquote($colName) . "='N'";
            }
        }
    }
    if ($new) {
        $sql_query = "INSERT INTO " . $groupTable
            . "(`usergroup`" . $cols . ")"
            . " VALUES"
            . " ('" . PMA_Util::sqlAddSlashes($userGroup) . "'" . $vals . ")";
    } else {
        $sql_query = "UPDATE " . $groupTable . " SET " . substr($colsNvals, 1)
            . " WHERE `usergroup`='" . PMA_Util::sqlAddSlashes($userGroup) . "'";
    }
    PMA_queryAsControlUser($sql_query, true);
}

/**
 * Get HTML snippet for display user properties
 *
 * @param boolean $dbname_is_wildcard whether database name is wildcard or not
 * @param type    $url_dbname         url database name that urlencode() string
 * @param string  $username           username
 * @param string  $hostname           host name
 * @param string  $dbname             database name
 * @param string  $tablename          table name
 *
 * @return string $html_output
 */
function PMA_getHtmlForDisplayUserProperties($dbname_is_wildcard,$url_dbname,
    $username, $hostname, $dbname, $tablename
) {
    $html_output = PMA_getHtmlHeaderForDisplayUserProperties(
        $dbname_is_wildcard, $url_dbname, $dbname, $username, $hostname, $tablename
    );

    $sql = "SELECT '1' FROM `mysql`.`user`"
        . " WHERE `User` = '" . PMA_Util::sqlAddSlashes($username) . "'"
        . " AND `Host` = '" . PMA_Util::sqlAddSlashes($hostname) . "';";

    $user_does_not_exists = (bool) ! $GLOBALS['dbi']->fetchValue($sql);

    if ($user_does_not_exists) {
        $html_output .= PMA_Message::error(
            __('The selected user was not found in the privilege table.')
        )->getDisplay();
        $html_output .= PMA_getHtmlForDisplayLoginInformationFields();
            //exit;
    }

    $class = ' class="ajax"';
    $_params = array(
        'username' => $username,
        'hostname' => $hostname,
    );
    if (strlen($dbname)) {
        $_params['dbname'] = $dbname;
        if (strlen($tablename)) {
            $_params['tablename'] = $tablename;
        }
    }

    $html_output .= '<form' . $class . ' name="usersForm" id="addUsersForm"'
        . ' action="server_privileges.php" method="post">' . "\n";
    $html_output .= PMA_URL_getHiddenInputs($_params);
    $html_output .= PMA_getHtmlToDisplayPrivilegesTable(
        PMA_ifSetOr($dbname, '*', 'length'),
        PMA_ifSetOr($tablename, '*', 'length')
    );

    $html_output .= '</form>' . "\n";

    if (! strlen($tablename) && empty($dbname_is_wildcard)) {

        // no table name was given, display all table specific rights
        // but only if $dbname contains no wildcards

        $html_output .= '<form action="server_privileges.php" '
            . 'id="db_or_table_specific_priv" method="post">' . "\n";

        // unescape wildcards in dbname at table level
        $unescaped_db = PMA_Util::unescapeMysqlWildcards($dbname);
        list($html_rightsTable, $found_rows)
            = PMA_getTableForDisplayAllTableSpecificRights(
                $username, $hostname, $unescaped_db
            );
        $html_output .= $html_rightsTable;

        if (! strlen($dbname)) {
            // no database name was given, display select db
            $html_output .= PMA_getHtmlForDisplaySelectDbInEditPrivs($found_rows);

        } else {
            $html_output .= PMA_displayTablesInEditPrivs($dbname, $found_rows);
        }
        $html_output .= '</fieldset>' . "\n";

        $html_output .= '<fieldset class="tblFooters">' . "\n"
           . '    <input type="submit" value="' . __('Go') . '" />'
           . '</fieldset>' . "\n"
           . '</form>' . "\n";
    }

    // Provide a line with links to the relevant database and table
    if (strlen($dbname) && empty($dbname_is_wildcard)) {
        $html_output .= PMA_getLinkToDbAndTable($url_dbname, $dbname, $tablename);

    }

    if (! strlen($dbname) && ! $user_does_not_exists) {
        //change login information
        $html_output .= PMA_getHtmlForChangePassword($username, $hostname);
        $html_output .= PMA_getChangeLoginInformationHtmlForm($username, $hostname);
    }

    return $html_output;
}

/**
 * Get queries for Table privileges to change or copy user
 *
 * @param string $user_host_condition user host condition to
                                      select relevent table privileges
 * @param array  $queries             queries array
 * @param string $username            username
 * @param string $hostname            host name
 *
 * @return array  $queries
 */
function PMA_getTablePrivsQueriesForChangeOrCopyUser($user_host_condition,
    $queries, $username, $hostname
) {
    $res = $GLOBALS['dbi']->query(
        'SELECT `Db`, `Table_name`, `Table_priv` FROM `mysql`.`tables_priv`'
        . $user_host_condition,
        $GLOBALS['userlink'],
        PMA_DatabaseInterface::QUERY_STORE
    );
    while ($row = $GLOBALS['dbi']->fetchAssoc($res)) {

        $res2 = $GLOBALS['dbi']->query(
            'SELECT `Column_name`, `Column_priv`'
            .' FROM `mysql`.`columns_priv`'
            .' WHERE `User`'
            .' = \'' . PMA_Util::sqlAddSlashes($_REQUEST['old_username']) . "'"
            .' AND `Host`'
            .' = \'' . PMA_Util::sqlAddSlashes($_REQUEST['old_username']) . '\''
            .' AND `Db`'
            .' = \'' . PMA_Util::sqlAddSlashes($row['Db']) . "'"
            .' AND `Table_name`'
            .' = \'' . PMA_Util::sqlAddSlashes($row['Table_name']) . "'"
            .';',
            null,
            PMA_DatabaseInterface::QUERY_STORE
        );

        $tmp_privs1 = PMA_extractPrivInfo($row);
        $tmp_privs2 = array(
            'Select' => array(),
            'Insert' => array(),
            'Update' => array(),
            'References' => array()
        );

        while ($row2 = $GLOBALS['dbi']->fetchAssoc($res2)) {
            $tmp_array = explode(',', $row2['Column_priv']);
            if (in_array('Select', $tmp_array)) {
                $tmp_privs2['Select'][] = $row2['Column_name'];
            }
            if (in_array('Insert', $tmp_array)) {
                $tmp_privs2['Insert'][] = $row2['Column_name'];
            }
            if (in_array('Update', $tmp_array)) {
                $tmp_privs2['Update'][] = $row2['Column_name'];
            }
            if (in_array('References', $tmp_array)) {
                $tmp_privs2['References'][] = $row2['Column_name'];
            }
        }
        if (count($tmp_privs2['Select']) > 0 && ! in_array('SELECT', $tmp_privs1)) {
            $tmp_privs1[] = 'SELECT (`' . join('`, `', $tmp_privs2['Select']) . '`)';
        }
        if (count($tmp_privs2['Insert']) > 0 && ! in_array('INSERT', $tmp_privs1)) {
            $tmp_privs1[] = 'INSERT (`' . join('`, `', $tmp_privs2['Insert']) . '`)';
        }
        if (count($tmp_privs2['Update']) > 0 && ! in_array('UPDATE', $tmp_privs1)) {
            $tmp_privs1[] = 'UPDATE (`' . join('`, `', $tmp_privs2['Update']) . '`)';
        }
        if (count($tmp_privs2['References']) > 0
            && ! in_array('REFERENCES', $tmp_privs1)
        ) {
            $tmp_privs1[]
                = 'REFERENCES (`' . join('`, `', $tmp_privs2['References']) . '`)';
        }

        $queries[] = 'GRANT ' . join(', ', $tmp_privs1)
            . ' ON ' . PMA_Util::backquote($row['Db']) . '.'
            . PMA_Util::backquote($row['Table_name'])
            . ' TO \'' . PMA_Util::sqlAddSlashes($username)
            . '\'@\'' . PMA_Util::sqlAddSlashes($hostname) . '\''
            . (in_array('Grant', explode(',', $row['Table_priv']))
            ? ' WITH GRANT OPTION;'
            : ';');
    }
    return $queries;
}

/**
 * Get queries for database specific privileges for change or copy user
 *
 * @param array  $queries  queries array with string
 * @param string $username username
 * @param string $hostname host name
 *
 * @return array $queries
 */
function PMA_getDbSpecificPrivsQueriesForChangeOrCopyUser(
    $queries, $username, $hostname
) {
    $user_host_condition = ' WHERE `User`'
        .' = \'' . PMA_Util::sqlAddSlashes($_REQUEST['old_username']) . "'"
        .' AND `Host`'
        .' = \'' . PMA_Util::sqlAddSlashes($_REQUEST['old_username']) . '\';';

    $res = $GLOBALS['dbi']->query(
        'SELECT * FROM `mysql`.`db`' . $user_host_condition
    );

    while ($row = $GLOBALS['dbi']->fetchAssoc($res)) {
        $queries[] = 'GRANT ' . join(', ', PMA_extractPrivInfo($row))
            .' ON ' . PMA_Util::backquote($row['Db']) . '.*'
            .' TO \'' . PMA_Util::sqlAddSlashes($username)
            . '\'@\'' . PMA_Util::sqlAddSlashes($hostname) . '\''
            . ($row['Grant_priv'] == 'Y' ? ' WITH GRANT OPTION;' : ';');
    }
    $GLOBALS['dbi']->freeResult($res);

    $queries = PMA_getTablePrivsQueriesForChangeOrCopyUser(
        $user_host_condition, $queries, $username, $hostname
    );

    return $queries;
}

/**
 * Get HTML for secondary level menu tabs on 'Users' page
 *
 * @param string $selfUrl Url of the file
 *
 * @return string HTML for secondary level menu tabs on 'Users' page
 */
function PMA_getHtmlForSubMenusOnUsersPage($selfUrl)
{
    $url_params = PMA_URL_getCommon();
    $items = array(
        array(
            'name' => __('Users overview'),
            'url' => 'server_privileges.php'
        ),
        array(
            'name' => __('User groups'),
            'url' => 'server_user_groups.php'
        )
    );

    $retval  = '<ul id="topmenu2">';
    foreach ($items as $item) {
        $class = '';
        if ($item['url'] === $selfUrl) {
            $class = ' class="tabactive"';
        }
        $retval .= '<li>';
        $retval .= '<a' . $class;
        $retval .= ' href="' . $item['url'] . '?' . $url_params . '">';
        $retval .= $item['name'];
        $retval .= '</a>';
        $retval .= '</li>';
    }
    $retval .= '</ul>';
    $retval .= '<div class="clearfloat"></div>';

    return $retval;
}
?>
