rule TTP_XOR_WriteProcessMemory_cae9 {
  strings:
    $key_cae9 = { 9d 9b [2] af b9 [2] a9 8c [2] 87 8c [2] b8 90 }

  condition:
    any of them
}