rule TTP_XOR_WriteProcessMemory_ceaf {
  strings:
    $key_ceaf = { 99 dd [2] ab ff [2] ad ca [2] 83 ca [2] bc d6 }

  condition:
    any of them
}