class ApplicationTarget(object):
    """Encapsulates constants for HealthVault ActionURL targets.

    After a user has made some change to HealthVault via the Shell Redirect
    Interface, they are redirected back to your application's ActionURL. To
    distinguish what action has occurred, HealthVault sends the target
    as a GET parameter. For example::

        http://ActionURL?target=AppAuthSuccess

    For more information, see the `HealthVault documentation on application
    targets <http://msdn.microsoft.com/en-us/library/ff803620.aspx#returnApplicationTargets>`_.
    """
    APPAUTHINVALIDRECORD = 'AppAuthInvalidRecord'
    APPAUTHREJECT = 'AppAuthReject'
    APPAUTHSUCCESS = 'AppAuthSuccess'
    EDITRECORDCOMPLETE = 'EditRecordComplete'
    EDITRECORDCANCEL = 'EditRecordCancel'
    EDITRECORDCANCELED = 'EditRecordCanceled'
    RECONCILECANCELED = 'ReconcileCanceled'
    RECONCILECOMPLETE = 'ReconcileComplete'
    RECONCILEFAILURE = 'ReconcileFailure'
    SELECTEDRECORDCHANGED = 'SelectedRecordChanged'
    SHARERECORDFAILED = 'ShareRecordFailed'
    SHARERECORDSUCCESS = 'ShareRecordSuccess'
    SIGNOUT = 'SignOut'

    @classmethod
    def all_targets(cls):
        """Returns a list of all possible application targets."""
        return [cls.APPAUTHINVALIDRECORD, cls.APPAUTHREJECT,
                cls.APPAUTHSUCCESS, cls.EDITRECORDCOMPLETE,
                cls.EDITRECORDCANCEL, cls.EDITRECORDCANCELED,
                cls.RECONCILECANCELED, cls.RECONCILECOMPLETE,
                cls.RECONCILEFAILURE, cls.SELECTEDRECORDCHANGED,
                cls.SHARERECORDFAILED, cls.SHARERECORDSUCCESS, cls.SIGNOUT]
