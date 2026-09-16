rule warning_exec_ocx_object {
  meta:
    is_exploit = true
    is_warning = false
    is_feature = true
    rank       = 5
    revision   = "1"
    date       = "July 29 2015"
    author     = "@tylabs"
    release    = "lite"
    copyright  = "QuickSand.io (c) Copyright 2015. All rights reserved."
    tlp        = "white"
    sigtype    = "cryptam_exploit"
    desc       = "OLE application command"

  strings:
    $s1 = "w:ocx w:data=\"DATA:application/x-oleobject"

  condition:
    1 of them
}