rule TTP_XOR_WriteProcessMemory_d654 {
  strings:
    $key_d654 = { 81 26 [2] b3 04 [2] b5 31 [2] 9b 31 [2] a4 2d }

  condition:
    any of them
}