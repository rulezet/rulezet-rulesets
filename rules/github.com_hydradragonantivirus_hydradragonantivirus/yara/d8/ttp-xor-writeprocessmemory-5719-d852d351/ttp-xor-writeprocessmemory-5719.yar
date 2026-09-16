rule TTP_XOR_WriteProcessMemory_5719 {
  strings:
    $key_5719 = { 00 6b [2] 32 49 [2] 34 7c [2] 1a 7c [2] 25 60 }

  condition:
    any of them
}