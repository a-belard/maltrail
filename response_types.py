class Response:
  def __init__(self, statusCode):
    self.stausCode = statusCode

class RequiredResponse(Response):
  def __init__(self, required):
    self.stausCode = 401
    self.required = required
    
  def get_obj(self):
        return {"statusCode": self.stausCode, "errorMessage": f'{self.required} is required'}
      
class InvalidResponse(Response):
  def __init__(self, invalid):
    self.stausCode = 400
    self.invalid = invalid
    
  def get_obj(self):
        return {"statusCode": self.stausCode, "errorMessage": f'Invalid {self.invalid}'}