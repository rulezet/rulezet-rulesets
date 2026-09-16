rule TTP_XOR_WriteProcessMemory_3cfe {
  strings:
    $key_3cfe = { 6b 8c [2] 59 ae [2] 5f 9b [2] 71 9b [2] 4e 87 }

  condition:
    any of them
}