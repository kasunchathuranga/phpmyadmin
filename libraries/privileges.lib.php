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
 * Returns edit link for a user.
 *
 * @param string $username  User name
 * @param string $hostname  Host name
 * @param string $dbname    Database name
 * @param string $tablename Table name
 *
 * @return HTML code with link
 */
function PMA_getUserEditLink($username, $hostname, $dbname = '', $tablename = '')
{
    return '<a class="edit_user_anchor ajax"'
        . ' href="server_privileges.php'
        . PMA_URL_getCommon(
            array(
                'username' => $username,
                'hostname' => $hostname,
                'dbname' => $dbname,
                'tablename' => $tablename,
            )
        )
        . '">'
        . PMA_Util::getIcon('b_usredit.png', __('Edit Privileges'))
        . '</a>';
}

/**
 * Extracts the privilege information of a priv table row
 *
 * @param array   $row        the row
 * @param boolean $enableHTML add <dfn> tag with tooltips
 *
 * @global  resource $user_link the database connection
 *
 * @return array
 */
function PMA_extractPrivInfo($row = '', $enableHTML = false)
{
    $grants = PMA_getGrantsArray();

    if (! empty($row) && isset($row['Table_priv'])) {
        $row1 = $GLOBALS['dbi']->fetchSingleRow(
            'SHOW COLUMNS FROM `mysql`.`tables_priv` LIKE \'Table_priv\';',
            'ASSOC', $GLOBALS['userlink']
        );
        $av_grants = explode(
            '\',\'',
            substr($row1['Type'], 5, strlen($row1['Type']) - 7)
        );
        unset($row1);
        $users_grants = explode(',', $row['Table_priv']);
        foreach ($av_grants as $current_grant) {
            $row[$current_grant . '_priv']
                = in_array($current_grant, $users_grants) ? 'Y' : 'N';
        }
        unset($current_grant);
    }

    $privs = array();
    $allPrivileges = true;
    foreach ($grants as $current_grant) {
        if ((! empty($row) && isset($row[$current_grant[0]]))
            || (empty($row) && isset($GLOBALS[$current_grant[0]]))
        ) {
            if ((! empty($row) && $row[$current_grant[0]] == 'Y')
                || (empty($row)
                && ($GLOBALS[$current_grant[0]] == 'Y'
                || (is_array($GLOBALS[$current_grant[0]])
                && count($GLOBALS[$current_grant[0]]) == $_REQUEST['column_count']
                && empty($GLOBALS[$current_grant[0] . '_none']))))
            ) {
                if ($enableHTML) {
                    $privs[] = '<dfn title="' . $current_grant[2] . '">'
                        . $current_grant[1] . '</dfn>';
                } else {
                    $privs[] = $current_grant[1];
                }
            } elseif (! empty($GLOBALS[$current_grant[0]])
                && is_array($GLOBALS[$current_grant[0]])
                && empty($GLOBALS[$current_grant[0] . '_none'])
            ) {
                if ($enableHTML) {
                    $priv_string = '<dfn title="' . $current_grant[2] . '">'
                        . $current_grant[1] . '</dfn>';
                } else {
                    $priv_string = $current_grant[1];
                }
                $privs[] = $priv_string . ' (`'
                    . join('`, `', $GLOBALS[$current_grant[0]]) . '`)';
            } else {
                $allPrivileges = false;
            }
        }
    }
    if (empty($privs)) {
        if ($enableHTML) {
            $privs[] = '<dfn title="' . __('No privileges.') . '">USAGE</dfn>';
        } else {
            $privs[] = 'USAGE';
        }
    } elseif ($allPrivileges
        && (! isset($_POST['grant_count']) || count($privs) == $_POST['grant_count'])
    ) {
        if ($enableHTML) {
            $privs = array('<dfn title="'
                . __('Includes all privileges except GRANT.')
                . '">ALL PRIVILEGES</dfn>'
            );
        } else {
            $privs = array('ALL PRIVILEGES');
        }
    }
    return $privs;
} // end of the 'PMA_extractPrivInfo()' function

/**
 * Get the grants array which contains all the privilege types
 * and relevent grant messages
 *
 * @return array
 */
function PMA_getGrantsArray()
{
    return array(
        array(
            'Select_priv',
            'SELECT',
            __('Allows reading data.')
        ),
        array(
            'Insert_priv',
            'INSERT',
            __('Allows inserting and replacing data.')
        ),
        array(
            'Update_priv',
            'UPDATE',
            __('Allows changing data.')
        ),
        array(
            'Delete_priv',
            'DELETE',
            __('Allows deleting data.')
        ),
        array(
            'Create_priv',
            'CREATE',
            __('Allows creating new databases and tables.')
        ),
        array(
            'Drop_priv',
            'DROP',
            __('Allows dropping databases and tables.')
        ),
        array(
            'Reload_priv',
            'RELOAD',
            __('Allows reloading server settings and flushing the server\'s caches.')
        ),
        array(
            'Shutdown_priv',
            'SHUTDOWN',
            __('Allows shutting down the server.')
        ),
        array(
            'Process_priv',
            'PROCESS',
            __('Allows viewing processes of all users')
        ),
        array(
            'File_priv',
            'FILE',
            __('Allows importing data from and exporting data into files.')
        ),
        array(
            'References_priv',
            'REFERENCES',
            __('Has no effect in this MySQL version.')
        ),
        array(
            'Index_priv',
            'INDEX',
            __('Allows creating and dropping indexes.')
        ),
        array(
            'Alter_priv',
            'ALTER',
            __('Allows altering the structure of existing tables.')
        ),
        array(
            'Show_db_priv',
            'SHOW DATABASES',
            __('Gives access to the complete list of databases.')
        ),
        array(
            'Super_priv',
            'SUPER',
            __(
                'Allows connecting, even if maximum number of connections '
                . 'is reached; required for most administrative operations '
                . 'like setting global variables or killing threads of other users.'
            )
        ),
        array(
            'Create_tmp_table_priv',
            'CREATE TEMPORARY TABLES',
            __('Allows creating temporary tables.')
        ),
        array(
            'Lock_tables_priv',
            'LOCK TABLES',
            __('Allows locking tables for the current thread.')
        ),
        array(
            'Repl_slave_priv',
            'REPLICATION SLAVE',
            __('Needed for the replication slaves.')
        ),
        array(
            'Repl_client_priv',
            'REPLICATION CLIENT',
            __('Allows the user to ask where the slaves / masters are.')
        ),
        array(
            'Create_view_priv',
            'CREATE VIEW',
            __('Allows creating new views.')
        ),
        array(
            'Event_priv',
            'EVENT',
            __('Allows to set up events for the event scheduler')
        ),
        array(
            'Trigger_priv',
            'TRIGGER',
            __('Allows creating and dropping triggers')
        ),
        // for table privs:
        array(
            'Create View_priv',
            'CREATE VIEW',
            __('Allows creating new views.')
        ),
        array(
            'Show_view_priv',
            'SHOW VIEW',
            __('Allows performing SHOW CREATE VIEW queries.')
        ),
        // for table privs:
        array(
            'Show view_priv',
            'SHOW VIEW',
            __('Allows performing SHOW CREATE VIEW queries.')
        ),
        array(
            'Create_routine_priv',
            'CREATE ROUTINE',
            __('Allows creating stored routines.')
        ),
        array(
            'Alter_routine_priv',
            'ALTER ROUTINE',
            __('Allows altering and dropping stored routines.')
        ),
        array(
            'Create_user_priv',
            'CREATE USER',
            __('Allows creating, dropping and renaming user accounts.')
        ),
        array(
            'Execute_priv',
            'EXECUTE',
            __('Allows executing stored routines.')
        ),
    );
}

/**
 * Get HTML for addUsersForm, This function call if isset($_REQUEST['adduser'])
 *
 * @param string $dbname database name
 *
 * @return string HTML for addUserForm
 */
function PMA_getHtmlForAddUser($dbname)
{
    $html_output = '<h2>' . "\n"
       . PMA_Util::getIcon('b_usradd.png') . __('Add user') . "\n"
       . '</h2>' . "\n"
       . '<form name="usersForm" class="ajax" id="addUsersForm" action="'
       . (empty($dbname) ? 'server_privileges.php' : 'db_privileges.php')
       . '" method="post">' . "\n"
       . PMA_URL_getHiddenInputs(empty($dbname) ? '' : $dbname, '')
       . PMA_getHtmlForDisplayLoginInformationFields('new');

    $html_output .= '<fieldset id="fieldset_add_user_database">' . "\n"
        . '<legend>' . __('Database for user') . '</legend>' . "\n";

    $html_output .= PMA_Util::getCheckbox(
        'createdb-1',
        __('Create database with same name and grant all privileges.'),
        false, false
    );
    $html_output .= '<br />' . "\n";
    $html_output .= PMA_Util::getCheckbox(
        'createdb-2',
        __('Grant all privileges on wildcard name (username\\_%).'),
        false, false
    );
    $html_output .= '<br />' . "\n";

    if (! empty($dbname) ) {
        $html_output .= PMA_Util::getCheckbox(
            'createdb-3',
            sprintf(
                __('Grant all privileges on database &quot;%s&quot;.'),
                htmlspecialchars($dbname)
            ),
            true,
            false
        );
        $html_output .= '<input type="hidden" name="dbname" value="'
            . htmlspecialchars($dbname) . '" />' . "\n";
        $html_output .= '<br />' . "\n";
    }

    $html_output .= '</fieldset>' . "\n";
    $html_output .= PMA_getHtmlToDisplayPrivilegesTable('*', '*', false);
    $html_output .= '<fieldset id="fieldset_add_user_footer" class="tblFooters">'
        . "\n"
        . '<input type="submit" name="adduser_submit" '
        . 'value="' . __('Go') . '" />' . "\n"
        . '</fieldset>' . "\n"
        . '</form>' . "\n";

    return $html_output;
}

/**
 * Displays the fields used by the "new user" form as well as the
 * "change login information / copy user" form.
 *
 * @param string $mode are we creating a new user or are we just
 *                     changing  one? (allowed values: 'new', 'change')
 *
 * @global  array      $cfg     the phpMyAdmin configuration
 * @global  ressource  $user_link the database connection
 *
 * @return string $html_output  a HTML snippet
 */
function PMA_getHtmlForDisplayLoginInformationFields($mode = 'new')
{
    list($username_length, $hostname_length) = PMA_getUsernameAndHostnameLength();

    if (isset($GLOBALS['username']) && strlen($GLOBALS['username']) === 0) {
        $GLOBALS['pred_username'] = 'any';
    }
    $html_output = '<fieldset id="fieldset_add_user_login">' . "\n"
        . '<legend>' . __('Login Information') . '</legend>' . "\n"
        . '<div class="item">' . "\n"
        . '<label for="select_pred_username">' . "\n"
        . '    ' . __('User name:') . "\n"
        . '</label>' . "\n"
        . '<span class="options">' . "\n";

    $html_output .= '<select name="pred_username" id="select_pred_username" '
        . 'title="' . __('User name') . '"' . "\n";


    $html_output .= '        onchange="'
        . 'if (this.value == \'any\') {'
        . '    username.value = \'\'; '
        . '    user_exists_warning.style.display = \'none\'; '
        . '} else if (this.value == \'userdefined\') {'
        . '    username.focus(); username.select(); '
        . '}">' . "\n";

    $html_output .= '<option value="any"'
        . ((isset($GLOBALS['pred_username']) && $GLOBALS['pred_username'] == 'any')
            ? ' selected="selected"'
            : '') . '>'
        . __('Any user')
        . '</option>' . "\n";

    $html_output .= '<option value="userdefined"'
        . ((! isset($GLOBALS['pred_username'])
                || $GLOBALS['pred_username'] == 'userdefined'
            )
            ? ' selected="selected"'
            : '') . '>'
        . __('Use text field')
        . ':</option>' . "\n";

    $html_output .= '</select>' . "\n"
        . '</span>' . "\n";

    $html_output .= '<input type="text" name="username" class="autofocus"'
        . ' maxlength="' . $username_length . '" title="' . __('User name') . '"'
        . (empty($GLOBALS['username'])
           ? ''
           : ' value="' . htmlspecialchars(
               isset($GLOBALS['new_username'])
               ? $GLOBALS['new_username']
               : $GLOBALS['username']
           ) . '"'
        )
        . ' onchange="pred_username.value = \'userdefined\';" />' . "\n";

    $html_output .= '<div id="user_exists_warning"'
        . ' name="user_exists_warning" style="display:none;">'
        . PMA_Message::notice(
            __(
                'An account already exists with the same username '
                . 'but possibly a different hostname. '
                . 'Are you sure you wish to proceed?'
            )
        )->getDisplay()
        . '</div>';
    $html_output .= '</div>';

    $html_output .= '<div class="item">' . "\n"
        . '<label for="select_pred_hostname">' . "\n"
        . '    ' . __('Host:') . "\n"
        . '</label>' . "\n";

    $html_output .= '<span class="options">' . "\n"
        . '    <select name="pred_hostname" id="select_pred_hostname" '
        . 'title="' . __('Host') . '"' . "\n";
    $_current_user = $GLOBALS['dbi']->fetchValue('SELECT USER();');
    if (! empty($_current_user)) {
        $thishost = str_replace(
            "'",
            '',
            substr($_current_user, (strrpos($_current_user, '@') + 1))
        );
        if ($thishost == 'localhost' || $thishost == '127.0.0.1') {
            unset($thishost);
        }
    }
    $html_output .= '    onchange="'
        . 'if (this.value == \'any\') { '
        . '     hostname.value = \'%\'; '
        . '} else if (this.value == \'localhost\') { '
        . '    hostname.value = \'localhost\'; '
        . '} '
        . (empty($thishost)
            ? ''
            : 'else if (this.value == \'thishost\') { '
            . '    hostname.value = \'' . addslashes(htmlspecialchars($thishost))
            . '\'; '
            . '} '
        )
        . 'else if (this.value == \'hosttable\') { '
        . '    hostname.value = \'\'; '
        . '} else if (this.value == \'userdefined\') {'
        . '    hostname.focus(); hostname.select(); '
        . '}">' . "\n";
    unset($_current_user);

    // when we start editing a user, $GLOBALS['pred_hostname'] is not defined
    if (! isset($GLOBALS['pred_hostname']) && isset($GLOBALS['hostname'])) {
        switch (strtolower($GLOBALS['hostname'])) {
        case 'localhost':
        case '127.0.0.1':
            $GLOBALS['pred_hostname'] = 'localhost';
            break;
        case '%':
            $GLOBALS['pred_hostname'] = 'any';
            break;
        default:
            $GLOBALS['pred_hostname'] = 'userdefined';
            break;
        }
    }
    $html_output .=  '<option value="any"'
        . ((isset($GLOBALS['pred_hostname'])
                && $GLOBALS['pred_hostname'] == 'any'
            )
            ? ' selected="selected"'
            : '') . '>'
        . __('Any host')
        . '</option>' . "\n"
        . '<option value="localhost"'
        . ((isset($GLOBALS['pred_hostname'])
                && $GLOBALS['pred_hostname'] == 'localhost'
            )
            ? ' selected="selected"'
            : '') . '>'
        . __('Local')
        . '</option>' . "\n";
    if (! empty($thishost)) {
        $html_output .= '<option value="thishost"'
            . ((isset($GLOBALS['pred_hostname'])
                    && $GLOBALS['pred_hostname'] == 'thishost'
                )
                ? ' selected="selected"'
                : '') . '>'
            . __('This Host')
            . '</option>' . "\n";
    }
    unset($thishost);
    $html_output .= '<option value="hosttable"'
        . ((isset($GLOBALS['pred_hostname'])
                && $GLOBALS['pred_hostname'] == 'hosttable'
            )
            ? ' selected="selected"'
            : '') . '>'
        . __('Use Host Table')
        . '</option>' . "\n";

    $html_output .= '<option value="userdefined"'
        . ((isset($GLOBALS['pred_hostname'])
                && $GLOBALS['pred_hostname'] == 'userdefined'
            )
            ? ' selected="selected"'
            : '') . '>'
        . __('Use text field:') . '</option>' . "\n"
        . '</select>' . "\n"
        . '</span>' . "\n";

    $html_output .= '<input type="text" name="hostname" maxlength="'
        . $hostname_length . '" value="'
        . htmlspecialchars(isset($GLOBALS['hostname']) ? $GLOBALS['hostname'] : '')
        . '" title="' . __('Host')
        . '" onchange="pred_hostname.value = \'userdefined\';" />' . "\n"
        . PMA_Util::showHint(
            __(
                'When Host table is used, this field is ignored '
                . 'and values stored in Host table are used instead.'
            )
        )
        . '</div>' . "\n";

    $html_output .= '<div class="item">' . "\n"
        . '<label for="select_pred_password">' . "\n"
        . '    ' . __('Password:') . "\n"
        . '</label>' . "\n"
        . '<span class="options">' . "\n"
        . '<select name="pred_password" id="select_pred_password" title="'
        . __('Password') . '"' . "\n";

    $html_output .= '            onchange="'
        . 'if (this.value == \'none\') { '
        . '    pma_pw.value = \'\'; pma_pw2.value = \'\'; '
        . '} else if (this.value == \'userdefined\') { '
        . '    pma_pw.focus(); pma_pw.select(); '
        . '}">' . "\n"
        . ($mode == 'change' ? '<option value="keep" selected="selected">'
            . __('Do not change the password')
            . '</option>' . "\n" : '')
        . '<option value="none"';

    if (isset($GLOBALS['username']) && $mode != 'change') {
        $html_output .= '  selected="selected"';
    }
    $html_output .= '>' . __('No Password') . '</option>' . "\n"
        . '<option value="userdefined"'
        . (isset($GLOBALS['username']) ? '' : ' selected="selected"') . '>'
        . __('Use text field')
        . ':</option>' . "\n"
        . '</select>' . "\n"
        . '</span>' . "\n"
        . '<input type="password" id="text_pma_pw" name="pma_pw" '
        . 'title="' . __('Password') . '" '
        . 'onchange="pred_password.value = \'userdefined\';" />' . "\n"
        . '</div>' . "\n";

    $html_output .= '<div class="item" '
        . 'id="div_element_before_generate_password">' . "\n"
        . '<label for="text_pma_pw2">' . "\n"
        . '    ' . __('Re-type:') . "\n"
        . '</label>' . "\n"
        . '<span class="options">&nbsp;</span>' . "\n"
        . '<input type="password" name="pma_pw2" id="text_pma_pw2" '
        . 'title="' . __('Re-type') . '" '
        . 'onchange="pred_password.value = \'userdefined\';" />' . "\n"
        . '</div>' . "\n"
       // Generate password added here via jQuery
       . '</fieldset>' . "\n";

    return $html_output;
} // end of the 'PMA_displayUserAndHostFields()' function

/**
 * Get username and hostname length
 *
 * @return array username length and hostname length
 */
function PMA_getUsernameAndHostnameLength()
{
    $fields_info = $GLOBALS['dbi']->getColumns('mysql', 'user', null, true);
    $username_length = 16;
    $hostname_length = 41;
    foreach ($fields_info as $val) {
        if ($val['Field'] == 'User') {
            strtok($val['Type'], '()');
            $value = strtok('()');
            if (is_int($value)) {
                $username_length = $value;
            }
        } elseif ($val['Field'] == 'Host') {
            strtok($val['Type'], '()');
            $value = strtok('()');
            if (is_int($value)) {
                $hostname_length = $value;
            }
        }
    }
    return array($username_length, $hostname_length);
}

/**
 * Displays the privileges form table
 *
 * @param string  $db     the database
 * @param string  $table  the table
 * @param boolean $submit wheather to display the submit button or not
 *
 * @global  array      $cfg         the phpMyAdmin configuration
 * @global  ressource  $user_link   the database connection
 *
 * @return string html snippet
 */
function PMA_getHtmlToDisplayPrivilegesTable($db = '*',
    $table = '*', $submit = true
) {
    $html_output = '';

    if ($db == '*') {
        $table = '*';
    }

    if (isset($GLOBALS['username'])) {
        $username = $GLOBALS['username'];
        $hostname = $GLOBALS['hostname'];
        $sql_query = PMA_getSqlQueryForDisplayPrivTable(
            $db, $table, $username, $hostname
        );
        $row = $GLOBALS['dbi']->fetchSingleRow($sql_query);
    }
    if (empty($row)) {
        if ($table == '*') {
            if ($db == '*') {
                $sql_query = 'SHOW COLUMNS FROM `mysql`.`user`;';
            } elseif ($table == '*') {
                $sql_query = 'SHOW COLUMNS FROM `mysql`.`db`;';
            }
            $res = $GLOBALS['dbi']->query($sql_query);
            while ($row1 = $GLOBALS['dbi']->fetchRow($res)) {
                if (substr($row1[0], 0, 4) == 'max_') {
                    $row[$row1[0]] = 0;
                } else {
                    $row[$row1[0]] = 'N';
                }
            }
            $GLOBALS['dbi']->freeResult($res);
        } else {
            $row = array('Table_priv' => '');
        }
    }
    if (isset($row['Table_priv'])) {
        $row1 = $GLOBALS['dbi']->fetchSingleRow(
            'SHOW COLUMNS FROM `mysql`.`tables_priv` LIKE \'Table_priv\';',
            'ASSOC', $GLOBALS['userlink']
        );
        // note: in MySQL 5.0.3 we get "Create View', 'Show view';
        // the View for Create is spelled with uppercase V
        // the view for Show is spelled with lowercase v
        // and there is a space between the words

        $av_grants = explode(
            '\',\'',
            substr(
                $row1['Type'],
                strpos($row1['Type'], '(') + 2,
                strpos($row1['Type'], ')') - strpos($row1['Type'], '(') - 3
            )
        );
        unset($row1);
        $users_grants = explode(',', $row['Table_priv']);

        foreach ($av_grants as $current_grant) {
            $row[$current_grant . '_priv']
                = in_array($current_grant, $users_grants) ? 'Y' : 'N';
        }
        unset($row['Table_priv'], $current_grant, $av_grants, $users_grants);

        // get columns
        $res = $GLOBALS['dbi']->tryQuery(
            'SHOW COLUMNS FROM '
            . PMA_Util::backquote(
                PMA_Util::unescapeMysqlWildcards($db)
            )
            . '.' . PMA_Util::backquote($table) . ';'
        );
        $columns = array();
        if ($res) {
            while ($row1 = $GLOBALS['dbi']->fetchRow($res)) {
                $columns[$row1[0]] = array(
                    'Select' => false,
                    'Insert' => false,
                    'Update' => false,
                    'References' => false
                );
            }
            $GLOBALS['dbi']->freeResult($res);
        }
        unset($res, $row1);
    }
    // table-specific privileges
    if (! empty($columns)) {
        $html_output .= PMA_getHtmlForTableSpecificPrivileges(
            $username, $hostname, $db, $table, $columns, $row
        );
    } else {
        // global or db-specific
        $html_output .= PMA_getHtmlForGlobalOrDbSpecificPrivs($db, $table, $row);
    }
    $html_output .= '</fieldset>' . "\n";
    if ($submit) {
        $html_output .= '<fieldset id="fieldset_user_privtable_footer" '
            . 'class="tblFooters">' . "\n"
           . '<input type="submit" name="update_privs" '
            . 'value="' . __('Go') . '" />' . "\n"
           . '</fieldset>' . "\n";
    }
    return $html_output;
} // end of the 'PMA_displayPrivTable()' function

/**
 * Get HTML for global or database specific privileges
 *
 * @param string $db    the database
 * @param string $table the table
 * @param string $row   first row from result or boolean false
 *
 * @return string $html_output
 */
function PMA_getHtmlForGlobalOrDbSpecificPrivs($db, $table, $row)
{
    $privTable_names = array(0 => __('Data'),
        1 => __('Structure'),
        2 => __('Administration')
    );
    $privTable = array();
    // d a t a
    $privTable[0] = PMA_getDataPrivilegeTable($db);

    // s t r u c t u r e
    $privTable[1] = PMA_getStructurePrivilegeTable($table, $row);

    // a d m i n i s t r a t i o n
    $privTable[2] = PMA_getAdministrationPrivilegeTable($db);

    $html_output = '<input type="hidden" name="grant_count" value="'
        . (count($privTable[0])
            + count($privTable[1])
            + count($privTable[2])
            - (isset($row['Grant_priv']) ? 1 : 0)
        )
        . '" />';
    $html_output .= '<fieldset id="fieldset_user_global_rights"><legend>';
    if ($db == '*') {
        $html_output .= __('Global privileges');
    } else if ($table == '*') {
        $html_output .= __('Database-specific privileges');
    } else {
        $html_output .= __('Table-specific privileges');
    }
    $html_output .= '<input type="checkbox" id="addUsersForm_checkall" '
        . 'class="checkall_box" title="' . __('Check All') . '" /> '
        . '<label for="addUsersForm_checkall">' . __('Check All') . '</label> ';
    $html_output .= '</legend>';
    $html_output .= '<p><small><i>'
        . __('Note: MySQL privilege names are expressed in English')
        . '</i></small></p>';

    // Output the Global privilege tables with checkboxes
    $html_output .= PMA_getHtmlForGlobalPrivTableWithCheckboxes(
        $privTable, $privTable_names, $row
    );

    // The "Resource limits" box is not displayed for db-specific privs
    if ($db == '*') {
        $html_output .= PMA_getHtmlForDisplayResourceLimits($row);
    }
    // for Safari 2.0.2
    $html_output .= '<div class="clearfloat"></div>';

    return $html_output;
}

/**
 * Get data privilege table as an array
 *
 * @param string $db the database
 *
 * @return string data privilege table
 */
function PMA_getDataPrivilegeTable($db)
{
    $data_privTable = array(
        array('Select', 'SELECT', __('Allows reading data.')),
        array('Insert', 'INSERT', __('Allows inserting and replacing data.')),
        array('Update', 'UPDATE', __('Allows changing data.')),
        array('Delete', 'DELETE', __('Allows deleting data.'))
    );
    if ($db == '*') {
        $data_privTable[]
            = array('File',
                'FILE',
                __('Allows importing data from and exporting data into files.')
            );
    }
    return $data_privTable;
}

/**
 * Get structure privilege table as an array
 *
 * @param string $table the table
 * @param array  $row   first row from result or boolean false
 *
 * @return string structure privilege table
 */
function PMA_getStructurePrivilegeTable($table, $row)
{
    $structure_privTable = array(
        array('Create',
            'CREATE',
            ($table == '*'
                ? __('Allows creating new databases and tables.')
                : __('Allows creating new tables.')
            )
        ),
        array('Alter',
            'ALTER',
            __('Allows altering the structure of existing tables.')
        ),
        array('Index', 'INDEX', __('Allows creating and dropping indexes.')),
        array('Drop',
            'DROP',
            ($table == '*'
                ? __('Allows dropping databases and tables.')
                : __('Allows dropping tables.')
            )
        ),
        array('Create_tmp_table',
            'CREATE TEMPORARY TABLES',
            __('Allows creating temporary tables.')
        ),
        array('Show_view',
            'SHOW VIEW',
            __('Allows performing SHOW CREATE VIEW queries.')
        ),
        array('Create_routine',
            'CREATE ROUTINE',
            __('Allows creating stored routines.')
        ),
        array('Alter_routine',
            'ALTER ROUTINE',
            __('Allows altering and dropping stored routines.')
        ),
        array('Execute', 'EXECUTE', __('Allows executing stored routines.')),
    );
    // this one is for a db-specific priv: Create_view_priv
    if (isset($row['Create_view_priv'])) {
        $structure_privTable[] = array('Create_view',
            'CREATE VIEW',
            __('Allows creating new views.')
        );
    }
    // this one is for a table-specific priv: Create View_priv
    if (isset($row['Create View_priv'])) {
        $structure_privTable[] = array('Create View',
            'CREATE VIEW',
            __('Allows creating new views.')
        );
    }
    if (isset($row['Event_priv'])) {
        // MySQL 5.1.6
        $structure_privTable[] = array('Event',
            'EVENT',
            __('Allows to set up events for the event scheduler')
        );
        $structure_privTable[] = array('Trigger',
            'TRIGGER',
            __('Allows creating and dropping triggers')
        );
    }
    return $structure_privTable;
}

/**
 * Get administration privilege table as an array
 *
 * @param string $db the table
 *
 * @return string administration privilege table
 */
function PMA_getAdministrationPrivilegeTable($db)
{
    $administration_privTable = array(
        array('Grant',
            'GRANT',
            __(
                'Allows adding users and privileges '
                . 'without reloading the privilege tables.'
            )
        ),
    );
    if ($db == '*') {
        $administration_privTable[] = array('Super',
            'SUPER',
            __(
                'Allows connecting, even if maximum number '
                . 'of connections is reached; required for '
                . 'most administrative operations like '
                . 'setting global variables or killing threads of other users.'
            )
        );
        $administration_privTable[] = array('Process',
            'PROCESS',
            __('Allows viewing processes of all users')
        );
        $administration_privTable[] = array('Reload',
            'RELOAD',
            __('Allows reloading server settings and flushing the server\'s caches.')
        );
        $administration_privTable[] = array('Shutdown',
            'SHUTDOWN',
            __('Allows shutting down the server.')
        );
        $administration_privTable[] = array('Show_db',
            'SHOW DATABASES',
            __('Gives access to the complete list of databases.')
        );
    }
    $administration_privTable[] = array('Lock_tables',
        'LOCK TABLES',
        __('Allows locking tables for the current thread.')
    );
    $administration_privTable[] = array('References',
        'REFERENCES',
        __('Has no effect in this MySQL version.')
    );
    if ($db == '*') {
        $administration_privTable[] = array('Repl_client',
            'REPLICATION CLIENT',
            __('Allows the user to ask where the slaves / masters are.')
        );
        $administration_privTable[] = array('Repl_slave',
            'REPLICATION SLAVE',
            __('Needed for the replication slaves.')
        );
        $administration_privTable[] = array('Create_user',
            'CREATE USER',
            __('Allows creating, dropping and renaming user accounts.')
        );
    }
    return $administration_privTable;
}

/**
 * Get HTML snippet for global privileges table with check boxes
 *
 * @param array $privTable       privileges table array
 * @param array $privTable_names names of the privilege tables
 *                               (Data, Structure, Administration)
 * @param array $row             first row from result or boolean false
 *
 * @return string $html_output
 */
function PMA_getHtmlForGlobalPrivTableWithCheckboxes(
    $privTable, $privTable_names, $row
) {
    $html_output = '';
    foreach ($privTable as $i => $table) {
        $html_output .= '<fieldset>' . "\n"
            . '<legend>' . $privTable_names[$i] . '</legend>' . "\n";
        foreach ($table as $priv) {
            $html_output .= '<div class="item">' . "\n"
                . '<input type="checkbox" class="checkall"'
                . ' name="' . $priv[0] . '_priv" '
                . 'id="checkbox_' . $priv[0] . '_priv"'
                . ' value="Y" title="' . $priv[2] . '"'
                . (($row[$priv[0] . '_priv'] == 'Y')
                    ?  ' checked="checked"'
                    : ''
                )
                . '/>' . "\n"
                . '<label for="checkbox_' . $priv[0] . '_priv">'
                . '<code><dfn title="' . $priv[2] . '">'
                . $priv[1] . '</dfn></code></label>' . "\n"
                . '</div>' . "\n";
        }
        $html_output .= '</fieldset>' . "\n";
    }
    return $html_output;
}

/**
 * Get HTML for "Resource limits"
 *
 * @param array $row first row from result or boolean false
 *
 * @return string html snippet
 */
function PMA_getHtmlForDisplayResourceLimits($row)
{
    $html_output = '<fieldset>' . "\n"
        . '<legend>' . __('Resource limits') . '</legend>' . "\n"
        . '<p><small>'
        . '<i>' . __('Note: Setting these options to 0 (zero) removes the limit.')
        . '</i></small></p>' . "\n";

    $html_output .= '<div class="item">' . "\n"
        . '<label for="text_max_questions">'
        . '<code><dfn title="'
        . __(
            'Limits the number of queries the user may send to the server per hour.'
        )
        . '">'
        . 'MAX QUERIES PER HOUR'
        . '</dfn></code></label>' . "\n"
        . '<input type="number" name="max_questions" id="text_max_questions" '
        . 'value="' . $row['max_questions'] . '" '
        . 'size="6" maxlength="11" min="0" '
        . 'title="'
        . __(
            'Limits the number of queries the user may send to the server per hour.'
        )
        . '" />' . "\n"
        . '</div>' . "\n";

    $html_output .= '<div class="item">' . "\n"
        . '<label for="text_max_updates">'
        . '<code><dfn title="'
        . __(
            'Limits the number of commands that change any table '
            . 'or database the user may execute per hour.'
        ) . '">'
        . 'MAX UPDATES PER HOUR'
        . '</dfn></code></label>' . "\n"
        . '<input type="number" name="max_updates" id="text_max_updates" '
        . 'value="' . $row['max_updates'] . '" size="6" maxlength="11" min="0" '
        . 'title="'
        . __(
            'Limits the number of commands that change any table '
            . 'or database the user may execute per hour.'
        )
        . '" />' . "\n"
        . '</div>' . "\n";

    $html_output .= '<div class="item">' . "\n"
        . '<label for="text_max_connections">'
        . '<code><dfn title="'
        . __(
            'Limits the number of new connections the user may open per hour.'
        ) . '">'
        . 'MAX CONNECTIONS PER HOUR'
        . '</dfn></code></label>' . "\n"
        . '<input type="number" name="max_connections" id="text_max_connections" '
        . 'value="' . $row['max_connections'] . '" size="6" maxlength="11" min="0" '
        . 'title="' . __(
            'Limits the number of new connections the user may open per hour.'
        )
        . '" />' . "\n"
        . '</div>' . "\n";

    $html_output .= '<div class="item">' . "\n"
        . '<label for="text_max_user_connections">'
        . '<code><dfn title="'
        . __('Limits the number of simultaneous connections the user may have.')
        . '">'
        . 'MAX USER_CONNECTIONS'
        . '</dfn></code></label>' . "\n"
        . '<input type="number" name="max_user_connections" '
        . 'id="text_max_user_connections" '
        . 'value="' . $row['max_user_connections'] . '" size="6" maxlength="11" '
        . 'title="'
        . __('Limits the number of simultaneous connections the user may have.')
        . '" />' . "\n"
        . '</div>' . "\n";

    $html_output .= '</fieldset>' . "\n";

    return $html_output;
}

/**
 * update Data for information: Adds a user
 *
 * @param string $dbname      db name
 * @param string $username    user name
 * @param string $hostname    host name
 * @param string $password    password
 * @param bool   $is_menuwork is_menuwork set?
 *
 * @return array
 */
function PMA_addUser(
    $dbname, $username, $hostname,
    $password, $is_menuwork
) {
    $message = null;
    $queries = null;
    $queries_for_display = null;
    $sql_query = '';
    $_add_user_error = null;

    if ($_POST['pred_username'] == 'any') {
        $username = '';
    }
    switch ($_POST['pred_hostname']) {
    case 'any':
        $hostname = '%';
        break;
    case 'localhost':
        $hostname = 'localhost';
        break;
    case 'hosttable':
        $hostname = '';
        break;
    case 'thishost':
        $_user_name = $GLOBALS['dbi']->fetchValue('SELECT USER()');
        $hostname = substr($_user_name, (strrpos($_user_name, '@') + 1));
        unset($_user_name);
        break;
    }
    $sql = "SELECT '1' FROM `mysql`.`user`"
        . " WHERE `User` = '" . PMA_Util::sqlAddSlashes($username) . "'"
        . " AND `Host` = '" . PMA_Util::sqlAddSlashes($hostname) . "';";
    if ($GLOBALS['dbi']->fetchValue($sql) == 1) {
        $message = PMA_Message::error(__('The user %s already exists!'));
        $message->addParam(
            '[em]\'' . $username . '\'@\'' . $hostname . '\'[/em]'
        );
        $_REQUEST['adduser'] = true;
        $_add_user_error = true;
    } else {
        list($create_user_real, $create_user_show, $real_sql_query, $sql_query)
            = PMA_getSqlQueriesForDisplayAndAddUser(
                $username, $hostname, (isset ($password) ? $password : '')
            );

        if (empty($_REQUEST['change_copy'])) {
            $_error = false;

            if (isset($create_user_real)) {
                if (! $GLOBALS['dbi']->tryQuery($create_user_real)) {
                    $_error = true;
                }
                $sql_query = $create_user_show . $sql_query;
            }
            list($sql_query, $message) = PMA_addUserAndCreateDatabase(
                $_error, $real_sql_query, $sql_query, $username, $hostname,
                isset($dbname) ? $dbname : null
            );
            if (! empty($_REQUEST['userGroup']) && $is_menuwork) {
                PMA_setUserGroup($GLOBALS['username'], $_REQUEST['userGroup']);
            }

        } else {
            if (isset($create_user_real)) {
                $queries[] = $create_user_real;
            }
            $queries[] = $real_sql_query;
            // we put the query containing the hidden password in
            // $queries_for_display, at the same position occupied
            // by the real query in $queries
            $tmp_count = count($queries);
            if (isset($create_user_real)) {
                $queries_for_display[$tmp_count - 2] = $create_user_show;
            }
            $queries_for_display[$tmp_count - 1] = $sql_query;
        }
        unset($res, $real_sql_query);
    }

    return array(
        $message, $queries, $queries_for_display, $sql_query, $_add_user_error
    );
}

/**
 * Get SQL queries for Display and Add user
 *
 * @param string $username usernam
 * @param string $hostname host name
 * @param string $password password
 *
 * @return array ($create_user_real, $create_user_show,$real_sql_query, $sql_query)
 */
function PMA_getSqlQueriesForDisplayAndAddUser($username, $hostname, $password)
{
    $sql_query = '';
    $create_user_real = 'CREATE USER \''
        . PMA_Util::sqlAddSlashes($username) . '\'@\''
        . PMA_Util::sqlAddSlashes($hostname) . '\'';

    $real_sql_query = 'GRANT ' . join(', ', PMA_extractPrivInfo()) . ' ON *.* TO \''
        . PMA_Util::sqlAddSlashes($username) . '\'@\''
        . PMA_Util::sqlAddSlashes($hostname) . '\'';

    if ($_POST['pred_password'] != 'none' && $_POST['pred_password'] != 'keep') {
        $sql_query = $real_sql_query . ' IDENTIFIED BY \'***\'';
        $real_sql_query .= ' IDENTIFIED BY \''
            . PMA_Util::sqlAddSlashes($_POST['pma_pw']) . '\'';
        if (isset($create_user_real)) {
            $create_user_show = $create_user_real . ' IDENTIFIED BY \'***\'';
            $create_user_real .= ' IDENTIFIED BY \''
                . PMA_Util::sqlAddSlashes($_POST['pma_pw']) . '\'';
        }
    } else {
        if ($_POST['pred_password'] == 'keep' && ! empty($password)) {
            $real_sql_query .= ' IDENTIFIED BY PASSWORD \'' . $password . '\'';
            if (isset($create_user_real)) {
                $create_user_real .= ' IDENTIFIED BY PASSWORD \'' . $password . '\'';
            }
        }
        $sql_query = $real_sql_query;
        if (isset($create_user_real)) {
            $create_user_show = $create_user_real;
        }
    }

    if ((isset($_POST['Grant_priv']) && $_POST['Grant_priv'] == 'Y')
        || (isset($_POST['max_questions']) || isset($_POST['max_connections'])
        || isset($_POST['max_updates']) || isset($_POST['max_user_connections']))
    ) {
        $with_clause = PMA_getWithClauseForAddUserAndUpdatePrivs();
        $real_sql_query .= ' ' . $with_clause;
        $sql_query .= ' ' . $with_clause;
    }

    if (isset($create_user_real)) {
        $create_user_real .= ';';
        $create_user_show .= ';';
    }
    $real_sql_query .= ';';
    $sql_query .= ';';

    return array($create_user_real,
        $create_user_show,
        $real_sql_query,
        $sql_query
    );
}

/**
 * Get a WITH clause for 'update privileges' and 'add user'
 *
 * @return string $sql_query
 */
function PMA_getWithClauseForAddUserAndUpdatePrivs()
{
    $sql_query = '';
    if (isset($_POST['Grant_priv']) && $_POST['Grant_priv'] == 'Y') {
        $sql_query .= ' GRANT OPTION';
    }
    if (isset($_POST['max_questions'])) {
        $max_questions = max(0, (int)$_POST['max_questions']);
        $sql_query .= ' MAX_QUERIES_PER_HOUR ' . $max_questions;
    }
    if (isset($_POST['max_connections'])) {
        $max_connections = max(0, (int)$_POST['max_connections']);
        $sql_query .= ' MAX_CONNECTIONS_PER_HOUR ' . $max_connections;
    }
    if (isset($_POST['max_updates'])) {
        $max_updates = max(0, (int)$_POST['max_updates']);
        $sql_query .= ' MAX_UPDATES_PER_HOUR ' . $max_updates;
    }
    if (isset($_POST['max_user_connections'])) {
        $max_user_connections = max(0, (int)$_POST['max_user_connections']);
        $sql_query .= ' MAX_USER_CONNECTIONS ' . $max_user_connections;
    }
    return ((!empty($sql_query)) ? 'WITH' . $sql_query : '');
}

/**
 * Prepares queries for adding users and
 * also create database and return query and message
 *
 * @param boolean $_error         whether user create or not
 * @param string  $real_sql_query SQL query for add a user
 * @param string  $sql_query      SQL query to be displayed
 * @param string  $username       username
 * @param string  $hostname       host name
 * @param string  $dbname         database name
 *
 * @return array  $sql_query, $message
 */
function PMA_addUserAndCreateDatabase($_error, $real_sql_query, $sql_query,
    $username, $hostname, $dbname
) {
    if ($_error || ! $GLOBALS['dbi']->tryQuery($real_sql_query)) {
        $_REQUEST['createdb-1'] = $_REQUEST['createdb-2']
            = $_REQUEST['createdb-3'] = false;
        $message = PMA_Message::rawError($GLOBALS['dbi']->getError());
    } else {
        $message = PMA_Message::success(__('You have added a new user.'));
    }

    if (isset($_REQUEST['createdb-1'])) {
        // Create database with same name and grant all privileges
        $q = 'CREATE DATABASE IF NOT EXISTS '
            . PMA_Util::backquote(
                PMA_Util::sqlAddSlashes($username)
            ) . ';';
        $sql_query .= $q;
        if (! $GLOBALS['dbi']->tryQuery($q)) {
            $message = PMA_Message::rawError($GLOBALS['dbi']->getError());
        }

        /**
         * Reload the navigation
         */
        $GLOBALS['reload'] = true;
        $GLOBALS['db'] = $username;

        $q = 'GRANT ALL PRIVILEGES ON '
            . PMA_Util::backquote(
                PMA_Util::escapeMysqlWildcards(
                    PMA_Util::sqlAddSlashes($username)
                )
            ) . '.* TO \''
            . PMA_Util::sqlAddSlashes($username)
            . '\'@\'' . PMA_Util::sqlAddSlashes($hostname) . '\';';
        $sql_query .= $q;
        if (! $GLOBALS['dbi']->tryQuery($q)) {
            $message = PMA_Message::rawError($GLOBALS['dbi']->getError());
        }
    }

    if (isset($_REQUEST['createdb-2'])) {
        // Grant all privileges on wildcard name (username\_%)
        $q = 'GRANT ALL PRIVILEGES ON '
            . PMA_Util::backquote(
                PMA_Util::sqlAddSlashes($username) . '\_%'
            ) . '.* TO \''
            . PMA_Util::sqlAddSlashes($username)
            . '\'@\'' . PMA_Util::sqlAddSlashes($hostname) . '\';';
        $sql_query .= $q;
        if (! $GLOBALS['dbi']->tryQuery($q)) {
            $message = PMA_Message::rawError($GLOBALS['dbi']->getError());
        }
    }

    if (isset($_REQUEST['createdb-3'])) {
        // Grant all privileges on the specified database to the new user
        $q = 'GRANT ALL PRIVILEGES ON '
        . PMA_Util::backquote(
            PMA_Util::sqlAddSlashes($dbname)
        ) . '.* TO \''
        . PMA_Util::sqlAddSlashes($username)
        . '\'@\'' . PMA_Util::sqlAddSlashes($hostname) . '\';';
        $sql_query .= $q;
        if (! $GLOBALS['dbi']->tryQuery($q)) {
            $message = PMA_Message::rawError($GLOBALS['dbi']->getError());
        }
    }
    return array($sql_query, $message);
}

?>