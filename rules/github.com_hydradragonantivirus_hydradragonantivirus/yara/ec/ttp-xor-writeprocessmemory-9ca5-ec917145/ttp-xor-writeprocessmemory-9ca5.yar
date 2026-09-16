rule TTP_XOR_WriteProcessMemory_9ca5 {
  strings:
    $key_9ca5 = { cb d7 [2] f9 f5 [2] ff c0 [2] d1 c0 [2] ee dc }

  condition:
    any of them
}