rule mag_php_js {
    strings: 
        $ = "onepage|checkout|onestep|firecheckout|onestepcheckout"
        $ = "'one|check'"
    condition: any of them
}