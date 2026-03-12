async function startScan(){

const target = document.getElementById("target").value;

if(!target){
alert("Please enter a target URL");
return;
}

document.getElementById("status").innerText = "Scanning...";

try{

const response = await fetch("http://127.0.0.1:5000/scan",{
method:"POST",
headers:{
"Content-Type":"application/json"
},
body:JSON.stringify({target:target})
});

const data = await response.json();

/* SHOW RESULTS */

document.getElementById("result").innerText =
"Risk Score : " + data.risk_score;

document.getElementById("status").innerText =
"Severity : " + data.severity;

}catch(error){

document.getElementById("status").innerText =
"Scan Failed";

}

}