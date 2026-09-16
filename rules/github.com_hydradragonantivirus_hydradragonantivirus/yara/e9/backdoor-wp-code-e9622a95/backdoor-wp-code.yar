rule backdoor_wp_code {
  meta:
    description = "PHP - file backdoor_wp_code.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "de94bbc0d4fca3b778c6fad1a7719c8aacce8e464be65864e41abefc0326ac6f"

  strings:
    $s1  = "if(!empty($_POST['password']) && md5($_POST['password']) == SHELL_PASSWORD) {" fullword ascii
    $s2  = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
    $s3  = "if(empty($_COOKIE['password']) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
    $s4  = "Plugin URI: http://www.freetellafriend.com/get_button/" fullword ascii
    $s5  = "$taf_img = get_settings(\\'home\\') . \\'/wp-content/plugins/tell-a-friend/button.gif\\';" fullword ascii
    $s6  = "setcookie('password', SHELL_PASSWORD, time()+60*60*24);" fullword ascii
    $s7  = "define('SHELL_PASSWORD', 'a6a8cb877ee18215f2c0fc2a6c7b4f2a');" fullword ascii
    $s8  = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
    $s9  = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
    $s10 = "Author URI: http://www.freetellafriend.com/" fullword ascii
    $s11 = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
    $s12 = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
    $s13 = "if(empty($_REQUEST['wp_username']) || empty($_REQUEST['wp_password']) || empty($_REQUEST['wp_email'])){" fullword ascii
    $s14 = "print '<a href=\"'.$base_name.'\" target=\"_blank\">'.$base_name.'</a>';" fullword ascii
    $s15 = "define('PASSWORD_FILE', 'p.txt');" fullword ascii
    $s16 = "$new_posts_array[$i]['post_content'] = $posts_array[$i]->post_content;" fullword ascii
    $s17 = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
    $s18 = "print array_to_json(get_users());" fullword ascii
    $s19 = "if(!empty($_GET['get_users'])) {" fullword ascii
    $s20 = "if(function_exists('get_users')) {" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 30KB and
      (8 of them)
    ) or (all of them)
}