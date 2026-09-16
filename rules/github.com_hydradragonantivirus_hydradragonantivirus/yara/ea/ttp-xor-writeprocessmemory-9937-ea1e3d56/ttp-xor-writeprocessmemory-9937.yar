rule TTP_XOR_WriteProcessMemory_9937 {
  strings:
    $key_9937 = { ce 45 [2] fc 67 [2] fa 52 [2] d4 52 [2] eb 4e }

  condition:
    any of them
}