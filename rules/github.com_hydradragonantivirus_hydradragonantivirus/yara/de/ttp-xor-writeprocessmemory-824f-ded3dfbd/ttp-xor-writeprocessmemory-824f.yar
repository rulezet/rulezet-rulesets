rule TTP_XOR_WriteProcessMemory_824f {
  strings:
    $key_824f = { d5 3d [2] e7 1f [2] e1 2a [2] cf 2a [2] f0 36 }

  condition:
    any of them
}