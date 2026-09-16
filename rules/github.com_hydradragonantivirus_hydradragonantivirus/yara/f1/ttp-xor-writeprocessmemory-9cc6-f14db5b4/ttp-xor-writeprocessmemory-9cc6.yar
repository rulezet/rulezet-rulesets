rule TTP_XOR_WriteProcessMemory_9cc6 {
  strings:
    $key_9cc6 = { cb b4 [2] f9 96 [2] ff a3 [2] d1 a3 [2] ee bf }

  condition:
    any of them
}