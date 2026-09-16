rule TTP_XOR_WriteProcessMemory_1bcc {
  strings:
    $key_1bcc = { 4c be [2] 7e 9c [2] 78 a9 [2] 56 a9 [2] 69 b5 }

  condition:
    any of them
}