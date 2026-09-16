rule EquationGroup_morerats_client_noprep {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "a5b191a8ede8297c5bba790ef95201c516d64e2898efaeb44183f8fdfad578bb"
      id = "27e9e51a-c853-5dcc-97d2-d3d31c5ccfac"
   strings:
      $x1 = "storestr = 'echo -n \"%s\" | Store --nullterminate --file=\"%s\" --set=\"%s\"' % (nopenargs, outfile, VAR_NAME)" fullword ascii
      $x2 = "The NOPEN-args provided are injected into infile if it is a valid" fullword ascii
      $x3 = " -i                do not autokill after 5 hours" fullword ascii
   condition:
      ( filesize < 9KB and 1 of them )
}