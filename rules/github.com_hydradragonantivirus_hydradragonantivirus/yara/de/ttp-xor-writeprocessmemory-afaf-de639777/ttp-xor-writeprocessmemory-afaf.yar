rule TTP_XOR_WriteProcessMemory_afaf {
  strings:
    $key_afaf = { f8 dd [2] ca ff [2] cc ca [2] e2 ca [2] dd d6 }

  condition:
    any of them
}