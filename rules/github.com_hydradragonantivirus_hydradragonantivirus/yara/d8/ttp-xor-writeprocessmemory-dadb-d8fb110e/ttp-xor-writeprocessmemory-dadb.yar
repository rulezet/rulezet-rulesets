rule TTP_XOR_WriteProcessMemory_dadb {
  strings:
    $key_dadb = { 8d a9 [2] bf 8b [2] b9 be [2] 97 be [2] a8 a2 }

  condition:
    any of them
}