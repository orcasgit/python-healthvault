class ApplicationTarget(object):

    APPAUTHINVALIDRECORD = 'appauthinvalidrecord'
    APPAUTHREJECT = 'appauthreject'
    APPAUTHSUCCESS = 'appauthsuccess'
    EDITRECORDCOMPLETE = 'editrecordcomplete'
    EDITRECORDCANCEL = 'editrecordcancel'
    EDITRECORDCANCELED = 'editrecordcanceled'
    RECONCILECANCELED = 'reconcilecanceled'
    RECONCILECOMPLETE = 'reconcilecomplete'
    RECONCILEFAILURE = 'reconcilefailure'
    SELECTEDRECORDCHANGED = 'selectedrecordchanged'
    SHARERECORDFAILED = 'sharerecordfailed'
    SHARERECORDSUCCESS = 'sharerecordsuccess'
    SIGNOUT = 'signout'

    @classmethod
    def all_targets(cls):
        return [cls.APPAUTHINVALIDRECORD, cls.APPAUTHREJECT,
                cls.APPAUTHSUCCESS, cls.EDITRECORDCOMPLETE,
                cls.EDITRECORDCANCEL, cls.EDITRECORDCANCELED,
                cls.RECONCILECANCELED, cls.RECONCILECOMPLETE,
                cls.RECONCILEFAILURE, cls.SELECTEDRECORDCHANGED,
                cls.SHARERECORDFAILED, cls.SHARERECORDSUCCESS, cls.SIGNOUT]
