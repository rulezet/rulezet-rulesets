rule TTP_XOR_WriteProcessMemory_cebd {
  strings:
    $key_cebd = { 99 cf [2] ab ed [2] ad d8 [2] 83 d8 [2] bc c4 }

  condition:
    any of them
}