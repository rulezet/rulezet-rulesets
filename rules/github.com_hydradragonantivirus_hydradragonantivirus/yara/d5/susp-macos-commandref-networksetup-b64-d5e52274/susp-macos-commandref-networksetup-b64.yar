rule SUSP_MacOS_CommandRef_networksetup_b64 {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-23"
    version     = "1.0"
    description = "check for references to networksetup utility"

  strings:
    $ = "networksetup" base64 base64wide

  condition:
    all of them
}