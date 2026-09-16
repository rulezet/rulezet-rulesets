rule TTP_XOR_WriteProcessMemory_9967 {
  strings:
    $key_9967 = { ce 15 [2] fc 37 [2] fa 02 [2] d4 02 [2] eb 1e }

  condition:
    any of them
}