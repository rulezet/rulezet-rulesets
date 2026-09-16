rule warning_scriptbridge {
  meta:
    is_exploit = false
    is_warning = true
    is_feature = true
    rank       = 5
    revision   = "1"
    date       = "July 29 2015"
    author     = "@tylabs"
    release    = "lite"
    copyright  = "QuickSand.io (c) Copyright 2015. All rights reserved."
    tlp        = "white"
    sigtype    = "cryptam_exploit"
    desc       = "ScriptBridge may load remote exploit"

  strings:
    $s1 = "ScriptBridge.ScriptBridge.1"

  condition:
    1 of them
}