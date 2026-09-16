rule TTP_XOR_WriteProcessMemory_5bcc {
  strings:
    $key_5bcc = { 0c be [2] 3e 9c [2] 38 a9 [2] 16 a9 [2] 29 b5 }

  condition:
    any of them
}