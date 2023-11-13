function start_home() {
    console.log('start_home');
    let main_content_title = document.querySelector('#main-content-title');
    main_content_title.innerHTML = '<div style="display: flex;"><img class="big-logo" src="../img/home_logo.png" alt="home logo"><h1>HOME</h1></div>';
}

function start_iam() {
    console.log('start_IAM');
    let main_content_title = document.querySelector('#main-content-title');
    main_content_title.innerHTML = '<div style="display: flex;"><img class="big-logo" src="../img/iam_logo.png" alt="IAM logo"><h1>IAM</h1></div>';
}

function start_ec2() {
    console.log('start_EC2');
    let main_content_title = document.querySelector('#main-content-title');
    main_content_title.innerHTML = '<div style="display: flex;"><img class="big-logo" src="../img/ec2_logo.png" alt="EC2 logo"><h1>EC2</h1></div>';
}

function start_vpc() {
    console.log('start_VPC');
    let main_content_title = document.querySelector('#main-content-title');
    main_content_title.innerHTML = '<div style="display: flex;"><img class="big-logo" src="../img/vpc_logo.png" alt="VPC logo"><h1>VPC</h1></div>';
}

function start_s3() {
    console.log('start_S3');
    let main_content_title = document.querySelector('#main-content-title');
    main_content_title.innerHTML = '<div style="display: flex;"><img class="big-logo" src="../img/s3_logo.png" alt="S3 logo"><h1>S3</h1></div>';
}

function start_rds() {
    console.log('start_RDS');
    let main_content_title = document.querySelector('#main-content-title');
    main_content_title.innerHTML = '<div style="display: flex;"><img class="big-logo" src="../img/rds_logo.png" alt="RDS logo"><h1>RDS</h1></div>';
}