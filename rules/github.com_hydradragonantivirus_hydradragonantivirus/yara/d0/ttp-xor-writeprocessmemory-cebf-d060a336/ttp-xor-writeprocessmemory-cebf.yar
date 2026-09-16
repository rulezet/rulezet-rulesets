rule TTP_XOR_WriteProcessMemory_cebf {
  strings:
    $key_cebf = { 99 cd [2] ab ef [2] ad da [2] 83 da [2] bc c6 }

  condition:
    any of them
}