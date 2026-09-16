rule TTP_XOR_WriteProcessMemory_43dc {
  strings:
    $key_43dc = { 14 ae [2] 26 8c [2] 20 b9 [2] 0e b9 [2] 31 a5 }

  condition:
    any of them
}