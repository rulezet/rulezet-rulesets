rule TTP_XOR_WriteProcessMemory_a98d {
  strings:
    $key_a98d = { fe ff [2] cc dd [2] ca e8 [2] e4 e8 [2] db f4 }

  condition:
    any of them
}