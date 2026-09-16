rule Speed_Challenge_network_encryption_decryption_algorithm_X4d4754__8_byt_51_ {
  strings:
    $a0 = { 4d 7f db 4c c8 62 82 7b a1 1f bb 82 91 78 42 0d 3c f6 45 65 fa 32 10 e7 93 d0 4c ed 38 0c 3b a1 42 9d 19 ba 60 1c d9 64 7a 83 10 41 3f d5 1e 6a b4 f8 31 }

  condition:
    $a0
}