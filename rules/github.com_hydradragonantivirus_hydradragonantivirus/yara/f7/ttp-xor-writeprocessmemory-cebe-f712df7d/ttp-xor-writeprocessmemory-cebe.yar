rule TTP_XOR_WriteProcessMemory_cebe {
  strings:
    $key_cebe = { 99 cc [2] ab ee [2] ad db [2] 83 db [2] bc c7 }

  condition:
    any of them
}