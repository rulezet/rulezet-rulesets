rule TTP_XOR_WriteProcessMemory_9496 {
  strings:
    $key_9496 = { c3 e4 [2] f1 c6 [2] f7 f3 [2] d9 f3 [2] e6 ef }

  condition:
    any of them
}