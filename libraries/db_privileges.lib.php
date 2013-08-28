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
 * Get the list of privileges and list of compared privileges as strings
 * and return a array that contains both strings
 *
 * @return array $list_of_privileges, $list_of_compared_privileges
 */
function PMA_getListOfPrivilegesAndComparedPrivileges()
{
    $list_of_privileges
        = '`User`, '
        . '`Host`, '
        . '`Select_priv`, '
        . '`Insert_priv`, '
        . '`Update_priv`, '
        . '`Delete_priv`, '
        . '`Create_priv`, '
        . '`Drop_priv`, '
        . '`Grant_priv`, '
        . '`Index_priv`, '
        . '`Alter_priv`, '
        . '`References_priv`, '
        . '`Create_tmp_table_priv`, '
        . '`Lock_tables_priv`, '
        . '`Create_view_priv`, '
        . '`Show_view_priv`, '
        . '`Create_routine_priv`, '
        . '`Alter_routine_priv`, '
        . '`Execute_priv`';

    $list_of_compared_privileges
        = '`Select_priv` = \'N\''
        . ' AND `Insert_priv` = \'N\''
        . ' AND `Update_priv` = \'N\''
        . ' AND `Delete_priv` = \'N\''
        . ' AND `Create_priv` = \'N\''
        . ' AND `Drop_priv` = \'N\''
        . ' AND `Grant_priv` = \'N\''
        . ' AND `References_priv` = \'N\''
        . ' AND `Create_tmp_table_priv` = \'N\''
        . ' AND `Lock_tables_priv` = \'N\''
        . ' AND `Create_view_priv` = \'N\''
        . ' AND `Show_view_priv` = \'N\''
        . ' AND `Create_routine_priv` = \'N\''
        . ' AND `Alter_routine_priv` = \'N\''
        . ' AND `Execute_priv` = \'N\'';

    if (PMA_MYSQL_INT_VERSION >= 50106) {
        $list_of_privileges .=
            ', `Event_priv`, '
            . '`Trigger_priv`';
        $list_of_compared_privileges .=
            ' AND `Event_priv` = \'N\''
            . ' AND `Trigger_priv` = \'N\'';
    }
    return array($list_of_privileges, $list_of_compared_privileges);
}

/**
 * Get the HTML for user form and check the privileges for a particular database.
 *
 * @return string $html_output
 */
function PMA_getHtmlForSpecificDbPrivileges()
{
    // check the privileges for a particular database.
    $html_output = '<form id="usersForm" action="server_privileges.php">'
        . '<fieldset>' . "\n";
    $html_output .= '<legend>' . "\n"
        . PMA_Util::getIcon('b_usrcheck.png')
        . '    '
        . sprintf(
            __('Users having access to &quot;%s&quot;'),
            '<a href="' . $GLOBALS['cfg']['DefaultTabDatabase'] . '?'
            . PMA_URL_getCommon($_REQUEST['db']) . '">'
            .  htmlspecialchars($_REQUEST['db'])
            . '</a>'
        )
        . "\n"
        . '</legend>' . "\n";

    $html_output .= '<table id="dbspecificuserrights" class="data">' . "\n"
        . '<thead>' . "\n"
        . '<tr><th>' . __('User') . '</th>' . "\n"
        . '<th>' . __('Host') . '</th>' . "\n"
        . '<th>' . __('Type') . '</th>' . "\n"
        . '<th>' . __('Privileges') . '</th>' . "\n"
        . '<th>' . __('Grant') . '</th>' . "\n"
        . '<th>' . __('Action') . '</th>' . "\n"
        . '</tr>' . "\n"
        . '</thead>' . "\n";
    $odd_row = true;
    // now, we build the table...
    list($list_of_privileges, $list_of_compared_privileges)
        = PMA_getListOfPrivilegesAndComparedPrivileges();

    $sql_query = '(SELECT ' . $list_of_privileges . ', `Db`'
        .' FROM `mysql`.`db`'
        .' WHERE \'' . PMA_Util::sqlAddSlashes($_REQUEST['db'])
        . "'"
        .' LIKE `Db`'
        .' AND NOT (' . $list_of_compared_privileges. ')) '
        .'UNION '
        .'(SELECT ' . $list_of_privileges . ', \'*\' AS `Db`'
        .' FROM `mysql`.`user` '
        .' WHERE NOT (' . $list_of_compared_privileges . ')) '
        .' ORDER BY `User` ASC,'
        .'  `Host` ASC,'
        .'  `Db` ASC;';
    $res = $GLOBALS['dbi']->query($sql_query);
    $row = $GLOBALS['dbi']->fetchAssoc($res);
    if ($row) {
        $found = true;
    }
    $html_output .= PMA_getHtmlTableBodyForSpecificDbPrivs(
        $found, $row, $odd_row, $res
    );
    $html_output .= '</table>'
        . '</fieldset>'
        . '</form>' . "\n";

    if ($GLOBALS['is_ajax_request'] == true
        && empty($_REQUEST['ajax_page_request'])
    ) {
        $message = PMA_Message::success(__('User has been added.'));
        $response = PMA_Response::getInstance();
        $response->addJSON('message', $message);
        $response->addJSON('user_form', $html_output);
        exit;
    } else {
        // Offer to create a new user for the current database
        $html_output .= '<fieldset id="fieldset_add_user">' . "\n"
           . '<legend>' . _pgettext('Create new user', 'New') . '</legend>' . "\n";

        $html_output .= '<a href="db_privileges.php'
            . PMA_URL_getCommon(
                array(
                    'adduser' => 1,
                    'db' => $_REQUEST['db'],
                )
            )
            .'" rel="'
            . PMA_URL_getCommon()
            . '" name="db_specific">' . "\n"
            . PMA_Util::getIcon('b_usradd.png')
            . '        ' . __('Add user') . '</a>' . "\n";

        $html_output .= '</fieldset>' . "\n";
    }
    return $html_output;
}

/**
 * Get HTML snippet for table body of specific database privileges
 *
 * @param boolean $found   whether user found or not
 * @param array   $row     array of rows from mysql,
 *                         db table with list of privileges
 * @param boolean $odd_row whether odd or not
 * @param string  $res     ran sql query
 *
 * @return string $html_output
 */
function PMA_getHtmlTableBodyForSpecificDbPrivs($found, $row, $odd_row,
    $res
) {
    $html_output = '<tbody>' . "\n";
    if ($found) {
        while (true) {
            // prepare the current user
            $current_privileges = array();
            $current_user = $row['User'];
            $current_host = $row['Host'];
            while ($row
                    && $current_user == $row['User']
                    && $current_host == $row['Host']
            ) {
                $current_privileges[] = $row;
                $row = $GLOBALS['dbi']->fetchAssoc($res);
            }
            $html_output .= '<tr '
                . 'class="noclick ' . ($odd_row ? 'odd' : 'even')
                . '">' . "\n"
                . '<td';
            if (count($current_privileges) > 1) {
                $html_output .= ' rowspan="' . count($current_privileges) . '"';
            }
            $html_output .= '>'
                . (empty($current_user)
                    ? '<span style="color: #FF0000">' . __('Any') . '</span>'
                    : htmlspecialchars($current_user)) . "\n"
                . '</td>' . "\n";

            $html_output .= '<td';
            if (count($current_privileges) > 1) {
                $html_output .= ' rowspan="' . count($current_privileges) . '"';
            }
            $html_output .= '>'
                . htmlspecialchars($current_host) . '</td>' . "\n";
            for ($i = 0; $i < count($current_privileges); $i++) {
                $current = $current_privileges[$i];
                $html_output .= '<td>' . "\n"
                   . '            ';
                if (! isset($current['Db']) || $current['Db'] == '*') {
                    $html_output .= __('global');
                } elseif (
                    $current['Db'] == PMA_Util::escapeMysqlWildcards(
                        $_REQUEST['db']
                    )
                ) {
                    $html_output .= __('database-specific');
                } else {
                    $html_output .= __('wildcard'). ': '
                        . '<code>' . htmlspecialchars($current['Db']) . '</code>';
                }
                $html_output .= "\n"
                   . '</td>' . "\n";

                $html_output .='<td>' . "\n"
                   . '<code>' . "\n"
                   . ''
                   . join(
                       ',' . "\n" . '                ',
                       PMA_extractPrivInfo($current, true)
                   )
                   . "\n"
                   . '</code>' . "\n"
                   . '</td>' . "\n";

                $html_output .= '<td>' . "\n"
                    . '' . ($current['Grant_priv'] == 'Y' ? __('Yes') : __('No'))
                    . "\n"
                    . '</td>' . "\n"
                    . '<td>' . "\n";
                $html_output .= PMA_getUserEditLink(
                    $current_user, $current_host,
                    (isset($current['Db']) && $current['Db'] != '*')
                    ? $current['Db'] : ''
                );
                $html_output .= '</td>' . "\n"
                   . '    </tr>' . "\n";
                if (($i + 1) < count($current_privileges)) {
                    $html_output .= '<tr '
                        . 'class="noclick ' . ($odd_row ? 'odd' : 'even') . '">'
                        . "\n";
                }
            }
            if (empty($row)) {
                break;
            }
            $odd_row = ! $odd_row;
        }
    } else {
        $html_output .= '<tr class="odd">' . "\n"
           . '<td colspan="6">' . "\n"
           . '            ' . __('No user found.') . "\n"
           . '</td>' . "\n"
           . '</tr>' . "\n";
    }
    $html_output .= '</tbody>' . "\n";

    return $html_output;
}

?>