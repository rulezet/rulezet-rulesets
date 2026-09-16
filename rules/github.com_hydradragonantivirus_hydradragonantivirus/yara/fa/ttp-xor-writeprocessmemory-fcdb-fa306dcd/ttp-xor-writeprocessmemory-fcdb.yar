rule TTP_XOR_WriteProcessMemory_fcdb {
  strings:
    $key_fcdb = { ab a9 [2] 99 8b [2] 9f be [2] b1 be [2] 8e a2 }

  condition:
    any of them
}