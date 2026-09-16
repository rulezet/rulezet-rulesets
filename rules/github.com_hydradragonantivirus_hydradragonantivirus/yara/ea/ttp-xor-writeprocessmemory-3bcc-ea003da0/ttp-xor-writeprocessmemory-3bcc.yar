rule TTP_XOR_WriteProcessMemory_3bcc {
  strings:
    $key_3bcc = { 6c be [2] 5e 9c [2] 58 a9 [2] 76 a9 [2] 49 b5 }

  condition:
    any of them
}