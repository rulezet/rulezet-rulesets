rule TTP_XOR_WriteProcessMemory_824c {
  strings:
    $key_824c = { d5 3e [2] e7 1c [2] e1 29 [2] cf 29 [2] f0 35 }

  condition:
    any of them
}