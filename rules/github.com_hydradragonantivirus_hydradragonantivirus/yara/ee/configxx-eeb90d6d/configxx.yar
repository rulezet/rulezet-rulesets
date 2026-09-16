rule configxx {
  meta:
    description = "case109 - file configxx.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "19cd21d9ac142fcb3394d8cf200ee8edc0d158c6f33a22d09da8d3e8e28b8955"

  strings:
    $s1  = "@symlink('/home/'.$user.'/public_html/supports/includes/iso4217.php',$user.'-hostbills-supports.txt');" fullword ascii
    $s2  = "@symlink('/home/'.$user.'/public_html/support/includes/iso4217.php',$user.'-hostbills-support.txt');" fullword ascii
    $s3  = "@symlink('/home/'.$user.'/public_html/blog/wp-config.php',$user.'-wp-blog.txt');" fullword ascii
    $s4  = "@symlink('/home/'.$user.'/public_html/blog/wp-config.php',$user.'-wp13-Wordpress.txt');" fullword ascii
    $s5  = "@symlink('/home/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-hostbills-hostbills.txt');" fullword ascii
    $s6  = "@symlink('/home/'.$user.'/public_html/blogs/wp-config.php',$user.'-wp-blogs.txt');" fullword ascii
    $s7  = "@symlink('/home/'.$user.'/public_html/clientsupport/configuration.php',$user.'-clientsupport.txt');" fullword ascii
    $s8  = "@symlink('/home/'.$user.'/public_html/hosting/configuration.php',$user.'-hosting.txt');" fullword ascii
    $s9  = "@symlink('/home/'.$user.'/public_html/requires/config.php',$user.'-AM4SS-hosting.txt');" fullword ascii
    $s10 = "@symlink('/home/'.$user.'/public_html/hosts/configuration.php',$user.'-hosts.txt');" fullword ascii
    $s11 = "@symlink('/home/'.$user.'/public_html/host/configuration.php',$user.'-host.txt');" fullword ascii
    $s12 = "@symlink('/home/'.$user.'/public_html/hostings/includes/iso4217.php',$user.'-hostbills-hostings.txt');" fullword ascii
    $s13 = "@symlink('/home/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-hostbills-hosting.txt');" fullword ascii
    $s14 = "@symlink('/home/'.$user.'/public_html/hostbill/includes/iso4217.php',$user.'-hostbills-hostbill.txt');" fullword ascii
    $s15 = "@symlink('/home/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-hostbills-billing.txt');" fullword ascii
    $s16 = "@symlink('/home/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-hostbills-billings.txt');" fullword ascii
    $s17 = "@symlink('/home/'.$user.'/public_html/supports/configuration.php',$user.'-supports.txt');" fullword ascii
    $s18 = "@symlink('/home/'.$user.'/public_html/hosts/includes/iso4217.php',$user.'-hostbills-hosts.txt');" fullword ascii
    $s19 = "@symlink('/home/'.$user.'/public_html/client/includes/iso4217.php',$user.'-hostbills-client.txt');" fullword ascii
    $s20 = "@symlink('/home/'.$user.'/public_html/host/includes/iso4217.php',$user.'-hostbills-host.txt');" fullword ascii

  condition:
    (uint16(0) == 0x683c and
      filesize < 40KB and
      (8 of them)
    ) or (all of them)
}