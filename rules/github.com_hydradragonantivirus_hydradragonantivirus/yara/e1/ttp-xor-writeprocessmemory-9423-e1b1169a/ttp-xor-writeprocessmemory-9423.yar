rule TTP_XOR_WriteProcessMemory_9423 {
  strings:
    $key_9423 = { c3 51 [2] f1 73 [2] f7 46 [2] d9 46 [2] e6 5a }

  condition:
    any of them
}