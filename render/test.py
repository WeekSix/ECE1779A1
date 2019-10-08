import uuid
import rendering


id=str(uuid.uuid4())

d={
  "id": "aws_test.png",
  "entities": [
    
    {
      "type": "sphere",
      "center": "-2.5,2.5,0",
      "radius": "2",
      "color": "0.4,0.5,0.1",
      "reflectivity": "0.8"
    },
    {
      "type": "sphere",
      "center": "-2.5,-2.5,0",
      "radius": "2",
      "color": "0.4,1,0.1",
      "reflectivity": "0.8"
    },
    {
      "type": "rectangle",
      "A": "-5,5,-3",
      "B": "-5,5,-3",
      "C": "5,5,-3",
      "color": "0.8,0.8,0.8",
      "reflectivity": "0.5"
    },
    {
      "position": "0,0,15",
      "type": "light"
    },
    {
      "type": "camera",
      "position": "0,-10,10",
      "center": "0,0,0",
      "width": "400",
      "height": "300"
    }
  ]
}
t={"id": "aws_test.png",
    "entities":[{"type":"rectangle",
      "A": "-5,5,0",
      "B": "5,-5,0",
      "C": "5,5,0",
      "color": "0.1,1,0.1",
      "reflectvity":"0.5"
      
    },
    {
      "type": "sphere",
      "center": "-2.5,2.5,1.75",
      "radius": "1",
      "color": "0,0.5,0.1",
      "reflectivity": "0.8"
    },
    {
      "type": "camera",
      "position": "0,-10,10",
      "center": "0,0,0",
      "width": "400",
      "height": "300"
    },
    {
      "position": "0,0,15",
      "type": "light"
    }
    ]
    }
rendering.lambda_handler(t, None)
