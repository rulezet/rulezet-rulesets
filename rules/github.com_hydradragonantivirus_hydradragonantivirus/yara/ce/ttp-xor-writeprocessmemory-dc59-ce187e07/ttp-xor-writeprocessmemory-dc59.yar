rule TTP_XOR_WriteProcessMemory_dc59 {
  strings:
    $key_dc59 = { 8b 2b [2] b9 09 [2] bf 3c [2] 91 3c [2] ae 20 }

  condition:
    any of them
}