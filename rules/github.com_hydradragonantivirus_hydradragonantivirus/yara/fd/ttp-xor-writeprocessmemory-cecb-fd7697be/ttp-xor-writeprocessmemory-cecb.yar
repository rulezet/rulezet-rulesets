rule TTP_XOR_WriteProcessMemory_cecb {
  strings:
    $key_cecb = { 99 b9 [2] ab 9b [2] ad ae [2] 83 ae [2] bc b2 }

  condition:
    any of them
}