rule SUSP_PList_Param_StartCalendarInterval_base64 {
  strings:
    $ = "<key>StartCalendarInterval</key>" base64 base64wide

  condition:
    all of them
}