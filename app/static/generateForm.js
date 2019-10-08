var rectangleForm, sphereForm, triangleForm, rectangle_num, sphere_num, triangle_num, error;
function makeJson(){
	var rectangles = parseInt(rectangle_num.val()), 
	spheres = parseInt(sphere_num.val()), 
	triangles = parseInt(triangle_num.val()),
	json = [], r_json = '', s_json = '', t_json = '', light_json='', camera_json='';
	
	if (rectangles + spheres + triangles <= 0) {
		error.innerHTML = 'Please add figures.';
		return false;
	}
	
	if (rectangles > 0){
		r_json += getRectangles(rectangles);
	}
	if (spheres > 0){
		s_json += getSpheres(spheres);
	}
	if (triangles > 0){
		t_json += getTriangles(triangles);
	}
	light_x = $("input[name='light_x']").val();
	light_y = $("input[name='light_y']").val();
	light_z = $("input[name='light_z']").val();
	light_json = {'type':'light', 'position': light_x +','+ light_y +','+ light_z}
	
	camera_x1 = $("input[name='camera_x1']").val();
	camera_y1 = $("input[name='camera_y1']").val();
	camera_z1 = $("input[name='camera_z1']").val();
	camera_x2 = $("input[name='camera_x2']").val();
	camera_y2 = $("input[name='camera_y2']").val();
	camera_z2 = $("input[name='camera_z2']").val();
	width = $("input[name='image_width']").val();
	height = $("input[name='image_height']").val();
	
	light_json = {'type':'light', 'position': light_x +','+ light_y +','+ light_z};
	camera_json = {'type':'camera',
		'position':camera_x1 +','+ camera_y1 +','+ camera_z1,
		'center':camera_x2 +','+ camera_y2 +','+ camera_z2,
		'width': width,
		'height': height
	};
	
	json = [r_json, s_json, t_json];
	json.push(JSON.stringify(light_json));
	json.push(JSON.stringify(camera_json));
	json = json.filter(function(string){ return string != '' });
	$("input[name='output_json']").val('[' + json.join(", ")+ ']');
	return true;
}

function getRectangles(number){
	var rectangle,rectangles_x, rectangles_y, rectangles_z, formId, form, points, r_json=[];
	for(i = 1; i <= number; i++) {
		formId = "rectangle_form" + i;
		form = $("#"+formId);
		rectangles_x = form.find("input[name='rectangle_x']").map(function(){
			return this.value;
		}).get();
		rectangles_y = form.find("input[name='rectangle_y']").map(function(){
			return this.value;
		}).get();
		rectangles_z = form.find("input[name='rectangle_z']").map(function(){
			return this.value;
		}).get();
		points = rectangles_x.map(function(value, index){
			return value +','+ rectangles_y[index] +','+ rectangles_z[index];
		});
		colorR = form.find("input[name='color_r']").val();
		colorG = form.find("input[name='color_g']").val();
		colorB = form.find("input[name='color_b']").val();
		rectangle = {
			"type":"rectangle",
			"A": points[0],
			"B": points[1],
			"C": points[2], 
			"reflectivity": form.find("input[name='reflectivity']").val(),
			"color": colorR +','+ colorG +','+ colorB
		};
		r_json.push(JSON.stringify(rectangle));
	}
	return r_json.join(", ");
}

function getSpheres(number){
	var sphere,sphere_x, sphere_y, sphere_z, formId, form, radius, s_json = [];
	for(i = 1; i <= number; i++) {
		formId = "sphere_form" + i;
		form = $("#"+formId);
		sphere_x = form.find("input[name='center_x']").val();
		sphere_y = form.find("input[name='center_y']").val();
		sphere_z = form.find("input[name='center_z']").val();
		radius = form.find("input[name='radius']").val();
		colorR = form.find("input[name='color_r']").val();
		colorG = form.find("input[name='color_g']").val();
		colorB = form.find("input[name='color_b']").val();
		sphere = {
			"type": "sphere",
			"center": sphere_x +','+ sphere_y +','+ sphere_z,
			"radius": radius,
			"reflectivity": form.find("input[name='reflectivity']").val(),
			"color": colorR +','+ colorG +','+ colorB
		};
		s_json.push(JSON.stringify(sphere));
	}
	return s_json.join(", ");
}

function getTriangles(number){
	var triangle,triangles_x, triangles_y,triangles_z, formId, form, points, t_json=[];
	for(i = 1; i <= number; i++) {
		formId = "triangle_form" + i;
		form = $("#"+formId);
		triangles_x = form.find("input[name='triangle_x']").map(function(){
			return this.value;
		}).get();
		triangles_y = form.find("input[name='triangle_y']").map(function(){
			return this.value;
		}).get();
		triangles_z = form.find("input[name='triangle_z']").map(function(){
			return this.value;
		}).get();
		points = triangles_x.map(function(value, index){
			return value +','+ triangles_y[index] +','+ triangles_z[index];
		});
		colorR = form.find("input[name='color_r']").val();
		colorG = form.find("input[name='color_g']").val();
		colorB = form.find("input[name='color_b']").val();
		triangle = {
			"type":"triangle",
			"A": points[0],
			"B": points[1],
			"C": points[2], 
			"reflectivity": form.find("input[name='reflectivity']").val(),
			"color": colorR +','+ colorG +','+ colorB
		};
		t_json.push(JSON.stringify(triangle));
	}
	return t_json.join(", ");
}
function incrementForm(type){
	var newId, number;
	error.innerHTML = '';
	switch(type){		
		case 0:
			number = parseInt(rectangle_num.val()) + 1;
			if (number > 5) {
			 	error.innerHTML = 'Maximum is 5';
			} else {
				newId = "rectangle_form" + number;
				$("#rectangle_forms")[0].innerHTML += '<div id="'+newId+'">'+ rectangleForm[0].innerHTML +'</div>';
				$("#rectangle_forms").find(".figure_id")[number - 1].innerHTML = number;
				rectangle_num.val(number);
			}
			break;
		case 1:
			number = parseInt(sphere_num.val()) + 1;
			if (number > 5){
				error.innerHTML = 'Maximum is 5';
			} else {
				newId = "sphere_form" + number;
				$("#sphere_forms")[0].innerHTML += '<div id="'+newId+'">'+ sphereForm[0].innerHTML +'</div>';
				$("#sphere_forms").find(".figure_id")[number - 1].innerHTML = number;
				sphere_num.val(number);
			}
			break;
		case 2:
			number = parseInt(triangle_num.val()) + 1;
			if (number > 5){
				error.innerHTML = 'Maximum is 5';
			} else {
				newId = "triangle_form" + number;
				$("#triangle_forms")[0].innerHTML += '<div id="'+newId+'">'+ triangleForm[0].innerHTML +'</div>';
				$("#triangle_forms").find(".figure_id")[number -1].innerHTML = number;
				triangle_num.val(number);
			}
			break;
	}
	return;
}
function decrementForm(type){
	var newId, number;
	error.innerHTML = '';
	switch(type){		
		case 0:
			number = parseInt(rectangle_num.val());
			if (number == 0) {
				error.innerHTML = 'Minimum is 0';
			} else {
				newId = "rectangle_form" + number;
				$("#rectangle_forms").find("#"+newId).remove();
				rectangle_num.val(--number);
			}
			break;
		case 1:
			number = parseInt(sphere_num.val());
			if (number == 0) {
				error.innerHTML = 'Minimum is 0';
			} else {
				newId = "sphere_form" + number;
				$("#sphere_forms").find("#"+newId).remove();
				sphere_num.val(--number);
			}
			break;
		case 2:
			number = parseInt(triangle_num.val());
			if (number == 0) {
				error.innerHTML = 'Minimum is 0';
			} else {
				newId = "triangle_form" + number;
				$("#triangle_forms").find("#"+newId).remove();
				triangle_num.val(--number);
			}
			break;
	}
	return;
}
$("body").ready(function(){
	error = $(".error_message")[0];
	rectangleForm = $("#rectangle_form1");
	sphereForm = $("#sphere_form1");
	triangleForm = $("#triangle_form1");
	rectangle_num = $("#rectangle_num");
	sphere_num = $("#sphere_num");
	triangle_num = $("#triangle_num");
});