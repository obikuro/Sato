# SATO.psd1
@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'SATO.psm1'

    # Version number of this module.
    ModuleVersion     = '1.0.0'

    # ID used to uniquely identify this module
    GUID              = '6c1d7489-5160-468e-b8d9-10d1092afd90'

    # Author of this module
    Author            = 'Edrian Miranda'

    # Copyright statement for this module
    Copyright         = 'BSD 3-Clause'

    # Description of the functionality provided by this module
    Description       = 'SATO (Secure Azure Token Operations) toolkit  for managing Azure tokens.'

    # Functions to export from this module
    FunctionsToExport = '*'

    # Private data for additional module metadata
    PrivateData       = @{

        PSData = @{

            Tags       = @('security', 'pentesting', 'red team', 'azure', 'token', 'cloud security')
            LicenseUri = 'https://github.com/obikuro/Sato/blob/main/LICENSE'
            ProjectUri = 'https://github.com/obikuro/Sato'

        } # End of PSData hashtable

    } # End of PrivateData hashtable
}
