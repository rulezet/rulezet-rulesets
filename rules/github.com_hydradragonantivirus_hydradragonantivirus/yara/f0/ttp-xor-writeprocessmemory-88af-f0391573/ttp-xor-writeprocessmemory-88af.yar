rule TTP_XOR_WriteProcessMemory_88af {
  strings:
    $key_88af = { df dd [2] ed ff [2] eb ca [2] c5 ca [2] fa d6 }

  condition:
    any of them
}