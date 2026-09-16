rule TTP_XOR_WriteProcessMemory_cc6d {
  strings:
    $key_cc6d = { 9b 1f [2] a9 3d [2] af 08 [2] 81 08 [2] be 14 }

  condition:
    any of them
}