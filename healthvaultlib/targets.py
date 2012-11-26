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
    APP_AUTH_INVALID_RECORD = 'AppAuthInvalidRecord'
    APP_AUTH_REJECT = 'AppAuthReject'
    APP_AUTH_SUCCESS = 'AppAuthSuccess'
    EDIT_RECORD_COMPLETE = 'EditRecordComplete'
    EDIT_RECORD_CANCEL = 'EditRecordCancel'
    EDIT_RECORD_CANCELED = 'EditRecordCanceled'
    RECONCILE_CANCELED = 'ReconcileCanceled'
    RECONCILE_COMPLETE = 'ReconcileComplete'
    RECONCILE_FAILURE = 'ReconcileFailure'
    SELECTED_RECORD_CHANGED = 'SelectedRecordChanged'
    SHARE_RECORD_FAILED = 'ShareRecordFailed'
    SHARE_RECORD_SUCCESS = 'ShareRecordSuccess'
    SIGN_OUT = 'SignOut'

    @classmethod
    def all_targets(cls):
        """Returns a list of all possible application targets."""
        return [cls.APP_AUTH_INVALID_RECORD, cls.APP_AUTH_REJECT,
                cls.APP_AUTH_SUCCESS, cls.EDIT_RECORD_COMPLETE,
                cls.EDIT_RECORD_CANCEL, cls.EDIT_RECORD_CANCELED,
                cls.RECONCILE_CANCELED, cls.RECONCILE_COMPLETE,
                cls.RECONCILE_FAILURE, cls.SELECTED_RECORD_CHANGED,
                cls.SHARE_RECORD_FAILED, cls.SHARE_RECORD_SUCCESS,
                cls.SIGN_OUT]
