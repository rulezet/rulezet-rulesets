rule TTP_XOR_WriteProcessMemory_d719 {
  strings:
    $key_d719 = { 80 6b [2] b2 49 [2] b4 7c [2] 9a 7c [2] a5 60 }

  condition:
    any of them
}