rule warning_rtf_embedded_file {
  meta:
    is_exploit = false
    is_warning = true
    is_feature = true
    rank       = 2
    revision   = "1"
    date       = "July 29 2015"
    author     = "@tylabs"
    release    = "lite"
    copyright  = "QuickSand.io (c) Copyright 2015. All rights reserved."
    tlp        = "white"
    sigtype    = "cryptam_warning"
    desc       = "TF embedded file package"

  strings:
    $s1 = /objdata.{1,300}\w*5\w*0\w*6\w*1\w*6\w*3\w*6\w*b\w*6\w*1\w*6\w*7\w*6\w*5\w*0\w*0/
    $s2 = "\\objclass Word.Document"

  condition:
    1 of them
}