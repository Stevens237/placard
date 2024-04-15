class Status:
    ACTIVATED = 'Activated'
    DEACTIVATED = 'Deactivated'
  
    @classmethod
    def is_activate(cls, status):
        return status == cls.ACTIVATE

    @classmethod
    def is_deactivate(cls, status):
        return status == cls.DEACTIVATE

    @classmethod
    def get_default_status(cls):
        return cls.ACTIVATE
     
    