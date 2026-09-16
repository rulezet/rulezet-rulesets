rule TTP_XOR_WriteProcessMemory_9dce {
  strings:
    $key_9dce = { ca bc [2] f8 9e [2] fe ab [2] d0 ab [2] ef b7 }

  condition:
    any of them
}